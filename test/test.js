'use strict';

const Assert = require('assert');
const Crypto = require('crypto');
const LUKS = require('../index');

/* CONSTANTS */
const LUKS_MAGIC          = new Buffer([0x4C,0x55,0x4B,0x53,0xBA,0xBE]); // partition header starts with magic {’L’,’U’,’K’,’S’, 0xBA, 0xBE }
const LUKS_VERSION        = 1;
const LUKS_DIGESTSIZE     = 20;                                          // length of master key checksum
const LUKS_SALTSIZE       = 32;                                          // length of the PBKDF2 salts
const LUKS_NUMKEYS        = 8;                                           // number of key slots
const LUKS_MKD_ITER       = 1000;                                        // number of iterations for the master key digest
const LUKS_KEY_DISABLED   = 0x0000DEAD;                                  // magic for disabled key slot in keyblock[i].active
const LUKS_KEY_ENABLED    = 0x00AC71F3;                                  // magic for enabled key slot in keyblock[i].active
const LUKS_STRIPES        = 4000;                                        // number of stripes for AFsplit.
const LUKS_ALIGN_KEYSLOTS = 4096;                                        // Default alignment for keyslot in bytes
const LUKS_SECTOR_SIZE    = 512;                                         // LUKS version 1 always use sector of fixed size 512 bytes

const LUKS_MAGIC_L          = 6;  // length ofthe LUKS magic value
const LUKS_CIPHERNAME_L     = 32; // maxsize of the ciphername
const LUKS_CIPHERMODE_L     = 32; // maxsize of the ciphermode
const LUKS_HASHSPEC_L       = 32; // maxsize of the hashspec
const UUID_STRING_L         = 40; // maxsize of the uuid, generally the size is 36

// Length of the LUKS header without the keyblock
const LUKS_HEADER_LENGTH =
    LUKS_MAGIC_L +      // magic
    2 +                 // version
    LUKS_CIPHERNAME_L + // ciphername
    LUKS_CIPHERMODE_L + // ciphermode
    LUKS_HASHSPEC_L +   // hashspec
    4 +                 // payloadOffset
    4 +                 // keyBytes or masterKeyLength
    LUKS_DIGESTSIZE +   // digest of the masterkey
    LUKS_SALTSIZE +     // digest salt
    4 +                 // digest iterations
    UUID_STRING_L;      // uuid

// Length of an individual keyblock
const LUKS_HEADER_KEYBLOCK_LENGTH =
    4 +             // active flag
    4 +             // password iterations
    LUKS_SALTSIZE + // password salt
    4 +             // key material offset
    4;              // stripes

const RANDOM_OPTIONS_AMOUNT = 1;

const DEFAULT_OPTIONS = {
	luks_numkeys: 8,
	luks_mkd_iter: 1000,
	luks_stripes: 4000,
	luks_align_keyslots: 4096,
	luks_sector_size: 512,
	luks_ciphername: 'aes',
	luks_ciphermode: 'xts-plain64',
	luks_hashspec: 'sha256',
	luks_key_bytes: 32,
	luks_pwd_iter: 2000
};

const MINIMUM_OPTIONS = {
	luks_numkeys: 1,
	luks_mkd_iter: 1,
	luks_stripes: 1,
	luks_align_keyslots: 1,
	luks_sector_size: 1,
	luks_ciphername: 'aes',
	luks_ciphermode: 'xts-plain64',
	luks_hashspec: 'sha1',
	luks_key_bytes: 32,
	luks_pwd_iter: 1
};

function getRandomInt(min, max) {
	min = Math.ceil(min);
	max = Math.floor(max);
	return Math.floor(Math.random() * (max - min)) + min;
}

function getRandomIntInclusive(min, max) {
	min = Math.ceil(min);
	max = Math.floor(max);
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

const ALLOWED_OPTIONS = {
	luks_numkeys: function () {
		return getRandomIntInclusive(1,24);
	},
	luks_mkd_iter: function () {
		return getRandomIntInclusive(1,262144);
	},
	luks_stripes: function () {
		return getRandomIntInclusive(1,4096);
	},
	luks_align_keyslots: function () {
		return getRandomIntInclusive(1,8192);
	},
	luks_sector_size: function () {
		return getRandomIntInclusive(1,4096);
	},
	luks_ciphername: function () {
		return 'aes';
	},
	luks_ciphermode: function () {
		return 'xts-plain64';
	},
	luks_hashspec: function () {
		const VALS = ['sha1','sha256','sha512','ripemd160'];
		return VALS[getRandomInt(0,VALS.length)];
	},
	luks_key_bytes: function () {
		const VALS = [32,64];
		return VALS[getRandomInt(0,VALS.length)];
	},
	luks_pwd_iter: function () {
		return getRandomIntInclusive(1,262144);
	}
};

function createRandomConfig () {
	var options = {};
	for (var field in ALLOWED_OPTIONS) {
		if (ALLOWED_OPTIONS.hasOwnProperty(field)) {
			options[field] = ALLOWED_OPTIONS[field]();
		}
	}
	return options;
}

function printConfig (config) {
	var string = 'Config {';
	for (var field in config) {
		if (config.hasOwnProperty(field)) {
			string += field + ' : ' + config[field] + ',';
		}
	}
	string += '};';
	console.log(string);
}

function verifyHeader (buffer, config) {
	Assert.notEqual(buffer,undefined);
	Assert.notEqual(buffer,null);
	Assert.ok(Buffer.isBuffer(buffer));
	var offset = 0;
	Assert.strictEqual(buffer.slice(offset,offset + LUKS_MAGIC_L).compare(LUKS_MAGIC), 0);
	offset += LUKS_MAGIC_L;
	Assert.strictEqual(buffer.readUInt16BE(offset), LUKS_VERSION);
	offset += 2;
	var luks_ciphername = new Buffer(LUKS_CIPHERNAME_L);
	luks_ciphername.fill(0);
	luks_ciphername.write(config.luks_ciphername);
	Assert.strictEqual(buffer.slice(offset,offset + LUKS_CIPHERNAME_L).compare(luks_ciphername), 0);
	offset += LUKS_CIPHERNAME_L;
	var luks_ciphermode = new Buffer(LUKS_CIPHERMODE_L);
	luks_ciphermode.fill(0);
	luks_ciphermode.write(config.luks_ciphermode);
	Assert.strictEqual(buffer.slice(offset, offset + LUKS_CIPHERMODE_L).compare(luks_ciphermode), 0);
	offset += LUKS_CIPHERMODE_L;
	var luks_hashspec = new Buffer(LUKS_HASHSPEC_L);
	luks_hashspec.fill(0);
	luks_hashspec.write(config.luks_hashspec);
	Assert.strictEqual(buffer.slice(offset, offset + LUKS_HASHSPEC_L).compare(luks_hashspec), 0);
	offset += LUKS_HASHSPEC_L;
	Assert.ok(buffer.readUInt32BE(offset) > 0); // payloadOffset
	offset += 4;
	Assert.strictEqual(buffer.readUInt32BE(offset), config.luks_key_bytes);
	offset += 4;
	offset += LUKS_DIGESTSIZE; // mkDigest
	offset += LUKS_SALTSIZE; // mkDigestSalt
	Assert.strictEqual(buffer.readUInt32BE(offset), config.luks_mkd_iter);
	offset += 4;
	offset += UUID_STRING_L; // uuid
	for (var i = 0; i < config.luks_numkeys; ++i) {
		var active = buffer.readUInt32BE(offset);
		if (active === LUKS_KEY_DISABLED) {
			Assert.strictEqual(active, LUKS_KEY_DISABLED);
			offset += 4;
			offset += 4; // password iterations
			offset += LUKS_SALTSIZE; // passwordSalt
			Assert.ok(buffer.readUInt32BE(offset) > 0); // keyMaterialOffset
			offset += 4;
			Assert.strictEqual(buffer.readUInt32BE(offset), config.luks_stripes);
			offset += 4;
		}
		else {
			Assert.strictEqual(active, LUKS_KEY_ENABLED);
			offset += 4;
			Assert.strictEqual(buffer.readUInt32BE(offset), config.luks_pwd_iter);
			offset += 4; // password iterations
			offset += LUKS_SALTSIZE; // passwordSalt
			Assert.ok(buffer.readUInt32BE(offset) > 0); // keyMaterialOffset
			offset += 4;
			Assert.strictEqual(buffer.readUInt32BE(offset), config.luks_stripes);
			offset += 4;
		}
	}
}

describe('LUKSHeaderCreation', function () {
	describe('#createLUKSHeaderWithMasterKey()', function () {
		var masterKeys = {};
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		function testOptions (options) {
			printConfig(options);
			if (!masterKeys[options.luks_key_bytes])
				masterKeys[options.luks_key_bytes] = Crypto.randomBytes(options.luks_key_bytes);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeaderWithMasterKey(masterKeys[options.luks_key_bytes]);
			verifyHeader(buffer, options);
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});
	});

	describe('#createLUKSHeader()', function () {
		var passKey = Crypto.randomBytes(getRandomIntInclusive(1,64));
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		function testOptions(options) {
			console.log('passKey : ',passKey.toString('hex'));
			printConfig(options);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeader(passKey);
			verifyHeader(buffer, options);
			Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH), LUKS_KEY_ENABLED);
			for (var j = 1; j < options.luks_numkeys; ++j) {
				Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (j*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_DISABLED);
			}
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});
	});
});

describe('LUKSHeaderModification', function () {
	this.retries(2);

	var passKey = Crypto.randomBytes(getRandomIntInclusive(1,64));

	describe('#addLUKSKeyWithMasterKey()', function () {
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		var masterKeys = {};
		function testOptions(options) {
			console.log('passKey : ',passKey.toString('hex'));
			printConfig(options);
			if (!masterKeys[options.luks_key_bytes])
				masterKeys[options.luks_key_bytes] = Crypto.randomBytes(options.luks_key_bytes);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeaderWithMasterKey(masterKeys[options.luks_key_bytes]);
			for (var i = 0; i < options.luks_numkeys; ++i) {
				Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (i*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_DISABLED);
			}
			for (var k = 0; k < options.luks_numkeys; ++k) {
				Assert.strictEqual(luks.addLUKSKeyWithMasterKey(buffer,masterKeys[options.luks_key_bytes],passKey), k);
				Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (k*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_ENABLED);
				for (var j = (k + 1); j < options.luks_numkeys; ++j) {
					Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (j*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_DISABLED);
				}
			}
			Assert.throws(() => {
				luks.addLUKSKeyWithMasterKey(buffer,masterKeys[options.luks_key_bytes],passKey);
			},/No remaining key slot/);
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});
	});

	describe('#addLUKSKey()', function () {
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		var existingPassKey = Crypto.randomBytes(getRandomIntInclusive(1,64));
		function testOptions(options) {
			console.log('existingPassKey : ',existingPassKey.toString('hex'));
			console.log('passKey : ',passKey.toString('hex'));
			printConfig(options);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeader(existingPassKey);
			Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH), LUKS_KEY_ENABLED);
			for (var i = 1; i < options.luks_numkeys; ++i) {
				Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (i*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_DISABLED);
			}
			for (var k = 1; k < options.luks_numkeys; ++k) {
				Assert.strictEqual(luks.addLUKSKey(buffer,existingPassKey,passKey), k);
				Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (k*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_ENABLED);
				for (var j = (k + 1); j < options.luks_numkeys; ++j) {
					Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (j*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_DISABLED);
				}
			}
			Assert.throws(() => {
				luks.addLUKSKey(buffer,existingPassKey,passKey);
			},/No remaining key slot/);
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});

	});

	describe('#removeLUKSKey()', function () {
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		function testOptions(options) {
			printConfig(options);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeader(passKey);
			Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH), LUKS_KEY_ENABLED);
			for (var i = 1; i < options.luks_numkeys; ++i) {
				Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH + (i*LUKS_HEADER_KEYBLOCK_LENGTH)), LUKS_KEY_DISABLED);
			}
			luks.removeLUKSKey(buffer, 0);
			Assert.strictEqual(buffer.readUInt32BE(LUKS_HEADER_LENGTH), LUKS_KEY_DISABLED);
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});
	});
});

describe('LUKSHeaderInformation', function () {
	var masterKeys = {};

	describe('#getLUKSKeyslotIndex()', function (done) {
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		function testOptions(options) {
			printConfig(options);
			if (!masterKeys[options.luks_key_bytes])
				masterKeys[options.luks_key_bytes] = Crypto.randomBytes(options.luks_key_bytes);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeaderWithMasterKey(masterKeys[options.luks_key_bytes]);
			var passKeys = [];
			for (var i = 0; i < options.luks_numkeys; ++i) {
				passKeys.push(Crypto.randomBytes(getRandomIntInclusive(1,64)));
				if (passKeys.length > 1) {
					for (var j = 0; j < passKeys.length - 1; ++j) {
						Assert.notStrictEqual(passKeys[j], passKeys[passKeys.length - 1]);
					}
				}
				Assert.strictEqual(luks.addLUKSKeyWithMasterKey(buffer,masterKeys[options.luks_key_bytes],passKeys[i]), i);
				Assert.strictEqual(luks.getLUKSKeyslotIndex(buffer,passKeys[i]), i);
			}
			for (var k = 0; k < options.luks_numkeys; ++k) {
				luks.removeLUKSKey(buffer,k);
				Assert.ok(luks.getLUKSKeyslotIndex(buffer,passKeys[k]) < 0);
			}
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});
	});

	describe('#getLUKSMasterKey()', function (done) {
		this.timeout(10000 + 10000 + (RANDOM_OPTIONS_AMOUNT * 20000));

		function testOptions(options) {
			printConfig(options);
			if (!masterKeys[options.luks_key_bytes])
				masterKeys[options.luks_key_bytes] = Crypto.randomBytes(options.luks_key_bytes);
			var luks = new LUKS(options);
			var buffer = luks.createLUKSHeaderWithMasterKey(masterKeys[options.luks_key_bytes]);
			var passKey = Crypto.randomBytes(getRandomIntInclusive(1,64));
			Assert.strictEqual(luks.addLUKSKeyWithMasterKey(buffer,masterKeys[options.luks_key_bytes],passKey), 0);
			var masterKey = luks.getLUKSMasterKey(buffer, passKey);
			Assert.notEqual(masterKey, undefined);
			Assert.notEqual(masterKey, null);
			Assert.ok(Buffer.isBuffer(masterKey));
			Assert.strictEqual(masterKey.length,masterKeys[options.luks_key_bytes].length);
			Assert.strictEqual(masterKey.compare(masterKeys[options.luks_key_bytes]),0);
			luks.removeLUKSKey(buffer,0);
			Assert.equal(luks.getLUKSMasterKey(buffer, passKey), null);
		}

		it('Default options', function (done) {
			testOptions(DEFAULT_OPTIONS);
			done();
		});
		it('Minimum options', function (done) {
			testOptions(MINIMUM_OPTIONS);
			done();
		});
		it('Random options', function (done) {
			for (var i = 0; i < RANDOM_OPTIONS_AMOUNT; ++i) {
				testOptions(createRandomConfig());
			}
			done();
		});
	});
});
