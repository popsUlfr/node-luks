// The MIT License
//
// Copyright (c) 2016 Philipp Richter <richterphilipp.pops@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

'use strict';

/**
 * @file Main LUKS file containing class and methods
 * @author Philipp Richter <richterphilipp.pops@gmail.com>
 */

const Crypto = require('crypto');
const Struct = require('struct');
const UUID = require('uuid');

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

const LUKS_CIPHERNAME = 'aes';         // default cipher name
const LUKS_CIPHERMODE = 'xts-plain64'; // default cipher mode
const LUKS_HASHSPEC   = 'sha256';      // default cipher mode
const LUKS_KEY_BYTES  = 32;            // default master key length, should accomodate the choosen cipher mode
const LUKS_PWD_ITER   = 2000;          // default password iterations

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

// Complete length of the header
const LUKS_HEADER_COMPLETE_LENGTH = LUKS_HEADER_LENGTH + (LUKS_HEADER_KEYBLOCK_LENGTH * LUKS_NUMKEYS);

/**
 * Returns the LUKS header c-style structure without the keyblocks
 * @private
 * @returns {Object} C-style struct
 */
function luksHeaderStruct () {
    return Struct()
        .chars('magic', LUKS_MAGIC_L, 'binary')
        .word16Ube('version')
        .charsnt('cipherName', LUKS_CIPHERNAME_L) // aes, twofish, serpent, cast5, cast6
        .charsnt('cipherMode', LUKS_CIPHERMODE_L) // ecb, cbc-plain, cbc-essiv:hash, xts-plain64
        .charsnt('hashSpec', LUKS_HASHSPEC_L)     // sha1, sha256, sha512, ripemd160
        .word32Ube('payloadOffset')
        .word32Ube('keyBytes')
        .chars('mkDigest', LUKS_DIGESTSIZE, 'binary')
        .chars('mkDigestSalt', LUKS_SALTSIZE, 'binary')
        .word32Ube('mkDigestIterations')
        .charsnt('uuid', UUID_STRING_L);
}

/**
 * Returns the header keyblock struct
 * @private
 * @returns {Object} C-style struct
 */
function luksHeaderKeyblockStruct () {
    return Struct()
        .word32Ube('active')
        /* parameters for PBKDF2 processing */
        .word32Ube('passwordIterations')
        .chars('passwordSalt', LUKS_SALTSIZE, 'binary')
        /* parameters for AF store/load */
        .word32Ube('keyMaterialOffset')
        .word32Ube('stripes');
}

/**
 * Returns the complete LUKS header
 * @private
 * @returns {Object} C-style struct
 */
function luksHeaderStructComplete (options) {
    return luksHeaderStruct()
        .array(
            'keyblock',
            options.luks_numkeys,
            luksHeaderKeyblockStruct()
        );
}

/**
 * @typedef LUKSOptions
 * @type {Object}
 * @property {number} luks_numkeys - Amount of key slots.
 * @property {number} luks_mkd_iter - Amount of iterations for the master key digest.
 * @property {number} luks_stripes - Amount of stripes for the anti-forensic split.
 * @property {number} luks_align_keyslots - Alignment for keyslot in bytes.
 * @property {number} luks_sector_size - LUKS version 1 always use sector of fixed size 512 bytes.
 * @property {string} luks_ciphername - Name of the cipher : aes, twofish, serpent, cast5, cast6.
 * @property {string} luks_ciphermode - Name of the cipher mode : ecb, cbc-plain, cbc-essiv:hash, xts-plain64.
 * @property {string} luks_hashspec - Name of the hash spec : sha1, sha256, sha512, ripemd160.
 * @property {number} luks_key_bytes - Length of the master key in bytes (32 => 256bits, 64 => 512bits).
 * @property {number} luks_pwd_iter - Number of iterations for the password in an individual keyslot.
 */

 /**
  * @typedef LUKSInfo
  * @type {Object}
  * @property {string} magic - LUKS magic value. (binary)
  * @property {number} version - LUKS header version.
  * @property {string} cipherName - Name of the cipher.
  * @property {string} cipherMode - Name of the ciphermode.
  * @property {string} hashSpec - Name of the hash spec.
  * @property {number} payloadOffset - Offset in sectors where the bulk data starts.
  * @property {number} keyBytes - Length of the master key in bytes.
  * @property {string} mkDigest - The digest of the masterKey. (binary)
  * @property {string} mkDigestSalt - The salt of the digest. (binary)
  * @property {number} mkDigestIterations - Amount of iterations for the master key digest.
  * @property {string} uuid - UUID for the header.
  * @property {number} numkeys - Amount of keyslots.
  * @property {number} emptyKeySlotIndex - Next available keyslot index.
  * @property {Object[]} keyblock - Array of keyblocks.
  * @property {number} keyblock[].active - Active flag of the keyslot.
  * @property {number} keyblock[].passwordIterations - Number of iterations for the password in an individual keyslot.
  * @property {string} keyblock[].passwordSalt - Salt used for during the password hashing.
  * @property {number} keyblock[].keyMaterialOffset - Offset of the key material in sectors.
  * @property {number} keyblock[].stripes - Amount of stripes for the anti-forensic split.
  */

/**
 * LUKS Constructor
 * @constructor
 * @public
 * @param {LUKSOptions} [options] Customizable variables, fallback to default options for missing fields
 */
function LUKS (options) {
    if (typeof options !== 'object')
        options = {};
    this.options = {};
    this.options.luks_numkeys = options.luks_numkeys || LUKS_NUMKEYS;
    this.options.luks_mkd_iter = options.luks_mkd_iter || LUKS_MKD_ITER;
    this.options.luks_stripes = options.luks_stripes || LUKS_STRIPES;
    this.options.luks_align_keyslots = options.luks_align_keyslots || LUKS_ALIGN_KEYSLOTS;
    this.options.luks_sector_size = options.luks_sector_size || LUKS_SECTOR_SIZE;
    this.options.luks_ciphername = options.luks_ciphername || LUKS_CIPHERNAME;
    this.options.luks_ciphermode = options.luks_ciphermode || LUKS_CIPHERMODE;
    this.options.luks_hashspec = options.luks_hashspec || LUKS_HASHSPEC;
    this.options.luks_key_bytes = options.luks_key_bytes || LUKS_KEY_BYTES;
    this.options.luks_pwd_iter = options.luks_pwd_iter || LUKS_PWD_ITER;
}

/**
 * Merges the supplied options with the defaults
 * @private
 * @param {LUKSOptions} options - Supplied options
 * @param {LUKSOptions} defaults - The default options to fallback to
 * @returns {LUKSOptions} The merged options
 */
function optionsHandler (options,defaults) {
    let newOptions = {};
    if (typeof options !== 'object')
        options = {};
    for (let option in defaults) {
        if (defaults.hasOwnProperty(option)) {
            newOptions[option] = options[option] || defaults[option];
        }
    }
    return newOptions;
}

/**
 * Handles the passKey error handling
 * @private
 * @throws Will throw if passKey is neither a string nor a buffer : 'PassKey is neither a Buffer nor a String'
 * @param {Buffer|string} passKey - Can be either a Buffer or a String
 * @returns {Buffer} The passKey buffer
 */
function passKeyHandler (passKey) {
    if (typeof passKey === 'string')
        passKey = new Buffer(passKey, 'binary');
    if (!Buffer.isBuffer(passKey))
        throw new Error('PassKey is neither a Buffer nor a String');
    return passKey;
}

/**
 * Rounds up a number representing the amount of sectors by aligning
 * @private
 * @param {number} number - the sectorcount
 * @param {number} sectorsize - the size of a sector in bytes (e.g.: 512)
 * @param {number} alignment - in bytes (e.g.: 4096)
 * @example
 * // returns 8
 * roundUp(2, 512, 4096);
 * @returns {number} the rounded up number
 */
function roundUp (number, sectorsize, alignment) {
    let bytes = Math.trunc(number * sectorsize);
    let diff = bytes % alignment;
    if (diff) {
        return Math.trunc((bytes - diff + alignment) / sectorsize);
    }
    return number;
}
/**
 * Generates a new LUKS header using a masterKey
 * At least one passkey should be added to be able to recover the masterkey afterwards
 * @private
 * @param {Buffer} masterKey - Buffer containing the masterKey
 * @param {LUKSOptions} options - options to be used during header creation
 * @returns {Buffer} the luks header without any passkeys
 */
function createLUKSHeaderWithMasterKey (masterKey, options) {
    let luks_phdr_struct = luksHeaderStructComplete(options);
    luks_phdr_struct.allocate();
    let buffer = luks_phdr_struct.buffer();
    buffer.fill(0);

    let luks_phdr = luks_phdr_struct.fields;
    luks_phdr.magic = LUKS_MAGIC.toString('binary');
    luks_phdr.version = LUKS_VERSION;
    luks_phdr.cipherName = options.luks_ciphername;
    luks_phdr.cipherMode = options.luks_ciphermode;
    luks_phdr.hashSpec = options.luks_hashspec;
    luks_phdr.keyBytes = masterKey.length;
    luks_phdr.mkDigestSalt = Crypto.randomBytes(LUKS_SALTSIZE).toString('binary');
    luks_phdr.mkDigestIterations = options.luks_mkd_iter;
    luks_phdr.mkDigest = Crypto.pbkdf2Sync(
        masterKey,
        (new Buffer(luks_phdr.mkDigestSalt,'binary')),
        luks_phdr.mkDigestIterations,
        LUKS_DIGESTSIZE,
        luks_phdr.hashSpec
    ).toString('binary');

    let baseOffset = Math.trunc(buffer.length / options.luks_sector_size) + 1;
    let keyMaterialSectors = Math.trunc((options.luks_stripes * luks_phdr.keyBytes) / options.luks_sector_size) + 1;
    for (let i = 0; i < options.luks_numkeys; ++i) {
        // Align keyslot up to multiple of LUKS_ALIGN_KEYSLOTS
        baseOffset = roundUp(baseOffset, options.luks_sector_size, options.luks_align_keyslots);
        luks_phdr.keyblock[i].active = LUKS_KEY_DISABLED;
        luks_phdr.keyblock[i].stripes = options.luks_stripes;
        luks_phdr.keyblock[i].keyMaterialOffset = baseOffset;
        baseOffset += keyMaterialSectors;
    }
    luks_phdr.payloadOffset = baseOffset;
    luks_phdr.uuid = UUID.v4();
    return Buffer.concat([buffer,(new Buffer((luks_phdr.payloadOffset * options.luks_sector_size) - buffer.length)).fill(0)]);
}

/**
 * XORs two buffers into a destination
 * @private
 * @param {Buffer} src1 - first source
 * @param {Buffer} src2 - second source
 * @param {Buffer} dest - destination of XOR
 * @param {number} size - amount of bytes to XOR
 */
function xorBlock (src1,src2,dest,size) {
    for (let i = 0; i < size; ++i) {
        dest[i] = src1[i] ^ src2[i];
    }
}

/**
 * Diffuses a block into a destination using sha1
 * @private
 * @param {Buffer} src - Source Buffer read from
 * @param {Buffer} dst - Write into
 * @param {number} size - length to handle
 */
function diffuse (src, dst, size) {
    const SHA1_DIGEST_SIZE = 20;
    let fullblocks = Math.trunc(size / SHA1_DIGEST_SIZE);
    let padding = size % SHA1_DIGEST_SIZE;

    /* hash block the whole data set with different IVs to produce
     * more than just a single data block
     */
    let i = 0;
    for (; i < fullblocks; ++i) {
        let sha1_hash = Crypto.createHash('sha1');
        let IV = new Buffer(4);
        IV.writeUInt32BE(i,0);
        sha1_hash.update(IV);
        let offset = SHA1_DIGEST_SIZE * i;
        sha1_hash.update(src.slice(offset,offset + SHA1_DIGEST_SIZE));
        sha1_hash.digest().copy(dst,offset);
    }

    if(padding) {
        let sha1_hash = Crypto.createHash('sha1');
        let IV = new Buffer(4);
        IV.writeUInt32BE(i,0);
        sha1_hash.update(IV);
        let offset = SHA1_DIGEST_SIZE * i;
        sha1_hash.update(src.slice(offset,offset + padding));
        sha1_hash.digest().copy(dst,offset,0,padding);
    }
}

/**
 * Anti forensic split into stripes
 * @private
 * @param {Buffer} src - Source block to split
 * @param {Buffer} dest - Write into
 * @param {number} blocksize - Size of the src buffer to handle
 * @param {number} stripes - Amount of stripes to split into
 */
function afSplit(src,dest,blocksize,stripes) {
    let bufblock = new Buffer(blocksize);
    bufblock.fill(0);
    /* process everything except the last block */
    let i = 0;
    for(; i < stripes - 1; ++i) {
        let offset = blocksize * i;
        Crypto.randomBytes(blocksize).copy(dest,offset);
        xorBlock(dest.slice(offset,offset+blocksize),bufblock,bufblock,blocksize);
        diffuse(bufblock,bufblock,blocksize);
    }
    /* the last block is computed */
    let offset = blocksize * i;
    xorBlock(src,bufblock,dest.slice(offset,offset+blocksize),blocksize);
}

/**
 * Anti forensic merge stripes
 * @private
 * @param {Buffer} src - Striped source to read from, should be at least blocksize * stripes
 * @param {Buffer} dst - Destination of at least blocksize to write the merged stripes into
 * @param {number} blocksize - Length of the block to write in bytes
 * @param {number} stripes - Amount of stripes
 */
function afMerge (src, dst, blocksize, stripes) {
    let bufblock = new Buffer(blocksize);
    bufblock.fill(0);
    let i = 0;
    for(; i < stripes - 1; ++i) {
        let offset = blocksize * i;
        xorBlock(src.slice(offset,offset+blocksize),bufblock,bufblock,blocksize);
        diffuse(bufblock,bufblock,blocksize);
    }
    let offset = blocksize * i;
    xorBlock(src.slice(offset,offset+blocksize),bufblock,dst,blocksize);
}

/**
 * Creates a cipher using info, key and sectorOffset as IV
 * @private
 * @throws Will throw if the cipher is unsupported : 'Unsupported cipher'
 * @throws Will throw if the keylength is unsupported : 'Unsupported encryption key length'
 * @param {LUKSInfo} info - as returned by getLUKSHeaderInfo()
 * @param {Buffer} key - used in cipher
 * @param {number} [sectorOffset] - used as IV (initialization vector)
 * @returns {stream.Duplex}
 */
function getCipher (info, key, sectorOffset = 0) {
    var cipher;
    if (info.cipherName !== 'aes' || info.cipherMode !== 'xts-plain64')
        throw new Error('Unsupported cipher');
    var iv_struct;
    switch (key.length) {
        case 32:
            // 16 bytes IV
            iv_struct = Struct().word64Ule('iv').word64Ule('pad');
            iv_struct.allocate();
            iv_struct.fields.iv = sectorOffset;
            iv_struct.fields.pad = 0;
            cipher = Crypto.createCipheriv('aes-128-xts',key,iv_struct.buffer());
            break;
        case 64:
            // 16 bytes IV
            iv_struct = Struct().word64Ule('iv')
            .word64Ule('pad1');
            iv_struct.allocate();
            iv_struct.fields.iv = sectorOffset;
            iv_struct.fields.pad1 = 0;
            cipher = Crypto.createCipheriv('aes-256-xts',key,iv_struct.buffer());
            break;
        default: throw new Error('Unsupported encryption key length');
    }
    return cipher;
}

/**
 * Creates a decipher using info, key and sectorOffset as IV
 * @private
 * @throws Will throw if the cipher is unsupported : 'Unsupported cipher'
 * @throws Will throw if the keylength is unsupported : 'Unsupported encryption key length'
 * @param {LUKSInfo} info - as returned by getLUKSHeaderInfo()
 * @param {Buffer} key - used in decipher
 * @param {number} [sectorOffset] -  used as IV
 * @returns {stream.Duplex}
 */
function getDecipher (info, key, sectorOffset = 0) {
    var cipher;
    if (info.cipherName !== 'aes' || info.cipherMode !== 'xts-plain64')
        throw new Error('Unsupported cipher');
    var iv_struct;
    switch (key.length) {
        case 32:
            // 16 bytes IV
            iv_struct = Struct().word64Ule('iv').word64Ule('pad');
            iv_struct.allocate();
            iv_struct.fields.iv = sectorOffset;
            iv_struct.fields.pad = 0;
            cipher = Crypto.createDecipheriv('aes-128-xts',key,iv_struct.buffer());
            break;
        case 64:
            // 16 bytes IV
            iv_struct = Struct().word64Ule('iv')
            .word64Ule('pad1');
            iv_struct.allocate();
            iv_struct.fields.iv = sectorOffset;
            iv_struct.fields.pad1 = 0;
            cipher = Crypto.createDecipheriv('aes-256-xts',key,iv_struct.buffer());
            break;
        default: throw new Error('Unsupported encryption key length');
    }
    return cipher;
}

/**
 * Encrypts a block
 * @private
 * @param {LUKSInfo} info - as returned by getLUKSHeaderInfo()
 * @param {Buffer} encryptionKey - key used to encrypt
 * @param {Buffer} block - data to encrypt using the cipher information in info
 * @param {number} [sectorOffset] - offset used for IV
 * @returns {Buffer} encrypted block
 */
function encrypt (info, encryptionKey, block, sectorOffset = 0) {
    let cipher = getCipher(info, encryptionKey, sectorOffset);
    let encryptedBlock = cipher.update(block);
    return Buffer.concat([encryptedBlock,cipher.final()]);
}

/**
 * Decrypts a block
 * @private
 * @param {LUKSInfo} info - as returned by getLUKSHeaderInfo()
 * @param {Buffer} decryptionKey - key used to decrypt
 * @param {Buffer} block - data to decrypt using the cipher information in info
 * @param {number} [sectorOffset] - offset used for IV
 * @returns {Buffer} decrypted block
 */
function decrypt (info, decryptionKey, block, sectorOffset = 0) {
    let cipher = getDecipher(info, decryptionKey, sectorOffset);
    let decryptedBlock = cipher.update(block);
    return Buffer.concat([decryptedBlock,cipher.final()]);
}

/**
 * Attempts decryption of the masterkey using keyslot at index
 * @private
 * @param {Buffer} luksHeader - the header
 * @param {LUKSInfo} info - as returned by getLUKSHeaderInfo()
 * @param {number} index - keyslot index
 * @param {Buffer} passKey - key to decrypt keyslot at index
 * @param {LUKSOptions} options - the options
 * @returns {Buffer} the masterkey if not empty or null
 */
function tryLUKSKeyslotIndex (luksHeader, info, index, passKey, options) {
    if (info.keyblock[index].active !== LUKS_KEY_ENABLED)
        return null;
    let passKeyPBKDF2 = Crypto.pbkdf2Sync(
        passKey,
        (new Buffer(info.keyblock[index].passwordSalt,'binary')),
        info.keyblock[index].passwordIterations,
        info.keyBytes,
        info.hashSpec
    );
    let offset = info.keyblock[index].keyMaterialOffset * options.luks_sector_size;
    let encryptedKey = luksHeader.slice(offset,offset + (info.keyBytes * info.keyblock[index].stripes));
    let splitKey = decrypt(info,passKeyPBKDF2,encryptedKey,info.keyblock[index].keyMaterialOffset);
    let masterKeyCandidate = new Buffer(info.keyBytes);
    afMerge(splitKey,masterKeyCandidate,info.keyBytes,info.keyblock[index].stripes);
    let masterKeyCandidatePBKDF2 = Crypto.pbkdf2Sync(
        masterKeyCandidate,
        (new Buffer(info.mkDigestSalt,'binary')),
        info.mkDigestIterations,
        LUKS_DIGESTSIZE,
        info.hashSpec
    );
    if (info.mkDigest !== masterKeyCandidatePBKDF2.toString('binary')) {
        return null;
    }
    return masterKeyCandidate;
}

/**
 * Parses a LUKS header for its information, also acts as header validation
 * @public
 * @throws Will throw if the luksHeader is not a buffer : 'Not a buffer'
 * @throws Will throw if the header is invalid : 'Not a luks header'
 * @param {Buffer} luksHeader - to fetch information for
 * @returns {LUKSInfo} header information
 */
LUKS.prototype.getLUKSHeaderInfo = function (luksHeader) {
    if (!Buffer.isBuffer(luksHeader))
        throw new Error('Not a buffer');
    if (LUKS_HEADER_LENGTH > luksHeader.length)
        throw new Error('Not a luks header');
    let luks_phdr_struct = luksHeaderStruct();
    luks_phdr_struct._setBuff(luksHeader);
    let luks_phdr = luks_phdr_struct.fields;
    if (luks_phdr.magic !== LUKS_MAGIC.toString('binary') ||
        luks_phdr.version !== LUKS_VERSION)
        throw new Error('Not a luks header');
    let info = {};
    for (let field in luks_phdr) {
        if (luks_phdr.hasOwnProperty(field)) {
            info[field] = luks_phdr[field];
        }
    }
    info.numkeys = 0;
    info.emptyKeySlotIndex = -1;
    info.keyblock = [];
    let luks_phdr_keyblock_struct = luksHeaderKeyblockStruct();
    for (let offset = LUKS_HEADER_LENGTH; (offset + LUKS_HEADER_KEYBLOCK_LENGTH) <= luksHeader.length; offset+=LUKS_HEADER_KEYBLOCK_LENGTH) {
        luks_phdr_keyblock_struct._setBuff(luksHeader.slice(offset,offset+LUKS_HEADER_KEYBLOCK_LENGTH));
        let luks_phdr_keyblock = luks_phdr_keyblock_struct.fields;
        if (luks_phdr_keyblock.active === LUKS_KEY_DISABLED ||
            luks_phdr_keyblock.active === LUKS_KEY_ENABLED) {
            let keyblock = {};
            for (let field in luks_phdr_keyblock) {
                if (luks_phdr_keyblock.hasOwnProperty(field)) {
                    keyblock[field] = luks_phdr_keyblock[field];
                }
            }
            info.keyblock.push(keyblock);
            if (info.emptyKeySlotIndex < 0 && luks_phdr_keyblock.active === LUKS_KEY_DISABLED)
                info.emptyKeySlotIndex = info.numkeys;
            ++info.numkeys;
        }
        else
            break;
    }
    return info;
};

/**
 * Adds a new LUKS key to the header
 * @public
 * @throws Will throw if the masterKey is not a buffer : 'MasterKey is not a buffer'
 * @throws Will throw if there are no remaining keyslots available : 'No remaining key slot'
 * @param {Buffer} luksHeader - the complete buffer containing the header
 * @param {Buffer} masterKey - the master key
 * @param {Buffer|string} passKey - the passkey to unlock the master key
 * @param {LUKSOptions} [options] - options to supply to the function
 * @returns {number} The keyslot the passKey has been added to
 */
LUKS.prototype.addLUKSKeyWithMasterKey = function (luksHeader, masterKey, passKey, options) {
    var self = this;
    if (!Buffer.isBuffer(masterKey))
        throw new Error('MasterKey is not a buffer');
    passKey = passKeyHandler(passKey);
    let info = self.getLUKSHeaderInfo(luksHeader);
    if (info.emptyKeySlotIndex < 0)
        throw new Error('No remaining key slot');
    options = optionsHandler(options,self.options);
    options.luks_numkeys = info.numkeys;
    let luks_phdr_struct = luksHeaderStructComplete(options);
    luks_phdr_struct._setBuff(luksHeader);
    let luks_phdr = luks_phdr_struct.fields;
    luks_phdr.keyblock[info.emptyKeySlotIndex].passwordIterations = options.luks_pwd_iter;
    luks_phdr.keyblock[info.emptyKeySlotIndex].passwordSalt = Crypto.randomBytes(LUKS_SALTSIZE).toString('binary');
    let splitKeyLength = info.keyBytes * info.keyblock[info.emptyKeySlotIndex].stripes;
    let splitKey = new Buffer(splitKeyLength);
    afSplit(masterKey,splitKey,info.keyBytes,info.keyblock[info.emptyKeySlotIndex].stripes);
    let passKeyPBKDF2 = Crypto.pbkdf2Sync(
        passKey,
        (new Buffer(luks_phdr.keyblock[info.emptyKeySlotIndex].passwordSalt,'binary')),
        luks_phdr.keyblock[info.emptyKeySlotIndex].passwordIterations,
        info.keyBytes,
        info.hashSpec
    );
    encrypt(info, passKeyPBKDF2, splitKey, info.keyblock[info.emptyKeySlotIndex].keyMaterialOffset)
    .copy(luksHeader,(info.keyblock[info.emptyKeySlotIndex].keyMaterialOffset * options.luks_sector_size));
    luks_phdr.keyblock[info.emptyKeySlotIndex].active = LUKS_KEY_ENABLED;
    return info.emptyKeySlotIndex;
};

/**
 * Fetches the keyslot index that matches the passKey
 * If multiple keyslots use the same passKey, then the first one to match will be returned
 * @public
 * @param {Buffer} luksHeader - the complete luks header
 * @param {Buffer|string} passKey - the passKey to search a matching keyslot for
 * @param {LUKSOptions} [options] - options to use during keyslot search
 * @returns {number} an index >0 if found, -1 if not
 */
LUKS.prototype.getLUKSKeyslotIndex = function (luksHeader, passKey, options) {
    var self = this;
    passKey = passKeyHandler(passKey);
    options = optionsHandler(options,self.options);
    let info = self.getLUKSHeaderInfo(luksHeader);
    for (let i = 0; i < info.numkeys; ++i) {
        if (tryLUKSKeyslotIndex(luksHeader, info, i, passKey, options) !== null)
            return i;
    }
    return -1;
};

/**
 * Recover the masterkey using a passkey
 * @public
 * @param {Buffer} luksHeader - the header
 * @param {Buffer|string} passKey - to unlock one of the keyslots
 * @param {LUKSOptions} [options] - options to supply to the function
 * @returns {Buffer} the masterkey or null if passkey did not match any stored key
 */
LUKS.prototype.getLUKSMasterKey = function (luksHeader, passKey, options) {
    var self = this;
    passKey = passKeyHandler(passKey);
    options = optionsHandler(options,self.options);
    let info = self.getLUKSHeaderInfo(luksHeader);
    for (let i = 0; i < info.numkeys; ++i) {
        let masterKeyCandidate = tryLUKSKeyslotIndex(luksHeader, info, i, passKey, options);
        if (masterKeyCandidate !== null) return masterKeyCandidate;
    }
    return null;
};

/**
 * Generates a new LUKS header using a masterKey
 * @public
 * @param {Buffer} masterKey - the length of the key should make sense for the chosen cipher mode
 * @param {LUKSOptions} [options] - options to use during header creation
 * @returns {Buffer} the generated luks header
 */
LUKS.prototype.createLUKSHeaderWithMasterKey = function (masterKey, options) {
    return createLUKSHeaderWithMasterKey(masterKey, optionsHandler(options,this.options));
};

/**
 * Creates a luks header initialized with a passKey
 * @public
 * @param {Buffer|string} passKey - used to decrypt the master key
 * @param {LUKSOptions} [options] - options to use during header creation
 * @returns {Buffer} the luks header
 */
LUKS.prototype.createLUKSHeader = function (passKey, options) {
    var self = this;
    options = optionsHandler(options,self.options);
    let masterKey = Crypto.randomBytes(options.luks_key_bytes);
    let buffer = createLUKSHeaderWithMasterKey(masterKey,options);
    self.addLUKSKeyWithMasterKey(buffer,masterKey,passKey,options);
    return buffer;
};

/**
 * Adds a new passKey to a luks header using an existing passKey
 * @public
 * @throws Will throw if the masterKey could not be unlocked : 'Could not unlock masterkey'
 * @param {Buffer} luksHeader - the luks header
 * @param {Buffer|string} existingPassKey - existing passKey to unlock masterkey
 * @param {Buffer|string} newPassKey - the new key to add to an available keyblock
 * @param {LUKSOptions} [options] - options to use during key insertion
 * @returns {number} The keyslot the passKey has been added to
 */
LUKS.prototype.addLUKSKey = function (luksHeader, existingPassKey, newPassKey, options) {
    var self = this;
    let masterKey = self.getLUKSMasterKey(luksHeader, existingPassKey, options);
    if (masterKey === null)
        throw new Error('Could not unlock masterkey');
    return self.addLUKSKeyWithMasterKey(luksHeader, masterKey, newPassKey, options);
};

/**
 * Removes the passKey at index setting the keyblock to disabled
 * @public
 * @throws Will throw if the index is out of bounds : 'Index is out of bounds'
 * @param {Buffer} luksHeader - the luks header
 * @param {number} index - index starting at 0 should not go over the maximum amount of keyslots
 * @param {LUKSOptions} [options] - options to use during key removal
 */
LUKS.prototype.removeLUKSKey = function (luksHeader, index, options) {
    var self = this;
    options = optionsHandler(options,self.options);
    let info = self.getLUKSHeaderInfo(luksHeader);
    if (index >= info.numkeys)
        throw new Error('Index is out of bounds');
    let luks_phdr_struct = luksHeaderStructComplete(options);
    luks_phdr_struct._setBuff(luksHeader);
    let luks_phdr = luks_phdr_struct.fields;
    luks_phdr.keyblock[index].active = LUKS_KEY_DISABLED;
    luks_phdr.keyblock[index].passwordIterations = 0;
    luks_phdr.keyblock[index].passwordSalt = (new Buffer (LUKS_SALTSIZE)).fill(0).toString('binary');
};

/**
 * Creates a duplex stream in which you write unencrypted data and read encrypted data
 * @public
 * @throws Will throw if the masterKey is not a buffer : 'MasterKey is not a buffer'
 * @param {Buffer} luksHeader - the luks header
 * @param {Buffer} masterKey - used to encrypt the data
 * @param {LUKSOptions} [options] - options to use during encryption
 * @returns {stream.Duplex}
 */
LUKS.prototype.encryptLUKSWithMasterKey = function (luksHeader, masterKey, options) {
    var self = this;
    if (!Buffer.isBuffer(masterKey))
        throw new Error('MasterKey is not a buffer');
    let info = self.getLUKSHeaderInfo(luksHeader);
    return getCipher(info, masterKey, info.payloadOffset);
};

/**
 * Creates a duplex stream in which you write unencrypted data and read encrypted data
 * @public
 * @throws Will throw if the masterKey could not be unlocked using the passKey : 'Could not unlock masterkey'
 * @param {Buffer} luksHeader - the luks header
 * @param {Buffer|string} passKey - passkey to decrypt masterkey
 * @param {LUKSOptions} [options] - options to use during encryption
 * @returns {stream.Duplex}
 */
LUKS.prototype.encryptLUKS = function (luksHeader, passKey, options) {
    var self = this;
    let masterKey = self.getLUKSMasterKey(luksHeader, passKey, options);
    if (masterKey === null)
        throw new Error('Could not unlock masterkey');
    return self.encryptLUKSWithMasterKey(luksHeader, masterKey, options);
};

/**
 * Creates a duplex stream in which you write encrypted data and read unencrypted data
 * @public
 * @throws Will throw if the masterKey is not a buffer : 'MasterKey is not a buffer'
 * @param {Buffer} luksHeader - the luks header
 * @param {Buffer} masterKey - masterKey to decrypt data
 * @param {LUKSOptions} [options] - options to use during encryption
 * @returns {stream.Duplex}
 */
LUKS.prototype.decryptLUKSWithMasterKey = function (luksHeader, masterKey, options) {
    var self = this;
    if (!Buffer.isBuffer(masterKey))
        throw new Error('MasterKey is not a buffer');
    let info = self.getLUKSHeaderInfo(luksHeader);
    return getDecipher(info, masterKey, info.payloadOffset);
};

/**
 * Creates a duplex stream in which you write encrypted data and read unencrypted data
 * @public
 * @throws Will throw if the masterKey could not be unlocked using the passKey : 'Could not unlock masterkey'
 * @param {Buffer} luksHeader - the luks header
 * @param {Buffer|string} passKey - passkey to decrypt masterkey
 * @param {LUKSOptions} [options] - options to use during encryption
 * @returns {stream.Duplex}
 */
LUKS.prototype.decryptLUKS = function (luksHeader, passKey, options) {
    var self = this;
    let masterKey = self.getLUKSMasterKey(luksHeader, passKey, options);
    if (masterKey === null)
        throw new Error('Could not unlock masterkey');
    return self.decryptLUKSWithMasterKey(luksHeader, masterKey, options);
};

module.exports = LUKS;
