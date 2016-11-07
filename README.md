# LUKS for nodejs

***

Implementation of the [Linux Unified Key Setup](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) for nodejs. The goal is to provide a way to encrypt/decrypt data in a secure and established way by following the [LUKS Spec](https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification). An unlockable master key using multiple pass keys serves to encrypt and decrypt the data.

While the default values adhere to the spec defaults, many variables are customizable in order to gain complete control over the data encryption.

**The resulting header may not be compatible with [cryptsetup(8)](https://linux.die.net/man/8/cryptsetup)**.

## Use cases
* Encrypt sensitive data using multiple passkeys (or only one of course)
* Store encrypted user files on a webserver which can only be read using the user password or an additional passphrase (e.g.: [ProtonMail](https://protonmail.com/security-details))
* Simply as powerful password hasher
* ...

## Install

```bash
$ npm install
```

## Test

```bash
$ npm test
```

## Function Reference

[**constructor**](#constructor)([[options](#options) : _Object_])

### LUKS Header Creation

[**createLUKSHeaderWithMasterKey**](#createluksheaderwithmasterkey)(masterKey : [_Buffer_](https://nodejs.org/api/buffer.html) [,[options](#options) : _Object_]) : [_Buffer_](https://nodejs.org/api/buffer.html)  
[**createLUKSHeader**](#createluksheader)(passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : [_Buffer_](https://nodejs.org/api/buffer.html)

### LUKS Header Information

[**getLUKSHeaderInfo**](#getluksheaderinfo)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html)) : _Object_  
[**getLUKSKeyslotIndex**](#getlukskeyslotindex)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : _Number_  
[**getLUKSMasterKey**](#getluksmasterkey)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_] : _Object_]) : [_Buffer_](https://nodejs.org/api/buffer.html)  

### LUKS Passkey Modification

[**addLUKSKeyWithMasterKey**](#addlukskeywithmasterkey)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), masterKey : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : _Number_  
[**addLUKSKey**](#addlukskey)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), existingPassKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_, newPassKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : _Number_  
[**removeLUKSKey**](#removelukskey)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), index : _Number_ [,[options](#options) : _Object_]) : _void_

### LUKS Data Encryption/Decryption

[**encryptLUKSWithMasterKey**](#encryptlukswithmasterkey)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), masterKey : [_Buffer_](https://nodejs.org/api/buffer.html) [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)  
[**encryptLUKS**](#encryptluks)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)  
[**decryptLUKSWithMasterKey**](#decryptlukswithmasterkey)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), masterKey : [_Buffer_](https://nodejs.org/api/buffer.html) [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)  
[**decryptLUKS**](#decryptluks)(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)  


## Options <a id="options"></a>

### Default options
```javascript
{
	luks_numkeys: 8,                /* amount of key slots ; default: 8 */
	luks_mkd_iter: 1000,            /* amount of iterations for the master key digest ; default: 1000 */
	                                /* cryptsetup infers the value using a benchmark */
	luks_stripes: 4000,             /* amount of stripes for the anti-forensic split ; default: 4000 */
	luks_align_keyslots: 4096,      /* alignment for keyslot in bytes ; default: 4096 */
	luks_sector_size: 512,          /* LUKS version 1 always use sector of fixed size 512 bytes ; default: 512 */
	luks_ciphername: 'aes',         /* Name of the cipher : aes, twofish, serpent, cast5, cast6 ; default: 'aes' */
	                                /* (IMPORTANT! Only 'aes' is supported in this version) */
	luks_ciphermode: 'xts-plain64', /* Name of the cipher mode : ecb, cbc-plain, cbc-essiv:hash, xts-plain64 ; default: 'xts-plain64' ; default: 'xts-plain64' */
	                                /* (IMPORTANT! Only 'xts-plain64' is supported in this version) */
	luks_hashspec: 'sha256',        /* Name of the hash spec : sha1, sha256, sha512, ripemd160 ; default: 'sha256' */
	luks_key_bytes: 32,             /* length of the master key in bytes (32 => 256bits, 64 => 512bits) ; default: 32 */
	                                /* depends on the cipher used (e.g.: 32 for aes-128-xts and 64 for aes-256-xts, the key is cut in half for xts) */
	luks_pwd_iter: 2000             /* number of iterations for the password in an individual keyslot ; default: 2000 */
	                                /* cryptsetup infers the value using a benchmark */
}
```

### Example for web oriented applications
```javascript
{
	luks_numkeys: 2,                /* 2 keyslots should be sufficient, at least one is used to store the PBKDF2'ed user password */
	luks_mkd_iter: 5000,            /* PBKDF2 iterations for the master key digest, this really depends on the performance of the server */
	                                /* too low and brute force attacks might be possible, too high and the system will spend a considerable amount of time to recover the master key */
	luks_stripes: 1,                /* striping does not seem as useful in this context, the key material area is effectively the size of the master key */
	luks_align_keyslots: 64,        /* set alignment to the same size as the master key */
	luks_sector_size: 64,           /* sector size also the same size as the master key */
	luks_ciphername: 'aes',         /* aes is hardware accelerated on most systems */
	luks_ciphermode: 'xts-plain64', /* the default of cryptsetup */
	luks_hashspec: 'sha512',        /* nice hashing :) */
	luks_key_bytes: 64,             /* 512bits for aes-xts corresponds to aes-256-xts, the key is split in 2 */
	luks_pwd_iter: 10000            /* PBKDF2 iterations for the passkey, same as for luks_mkd_iter it really depends on the performance of the machine */
	                                /* the user supplied passkey is not stored as is in a keyblock, it is run through PBKDF2 to get an entropy rich version of the passkey in order to encrypt the master key */
}
```

## LUKS Header Layout

```
+-----------------------------+----------+------+
|Field Name                   |Type      |Bytes |
+-----------------------------+----------+------+
|LUKS_MAGIC                   | chars    |     6|
|LUKS_VERSION                 | UInt16BE |     2|
|LUKS_CIPHERNAME              | charsnt  |    32|
|LUKS_CIPHERMODE              | charsnt  |    32|
|LUKS_HASHSPEC                | charsnt  |    32|
|LUKS_PAYLOAD_OFFSET          | UInt32BE |     4|
|LUKS_KEY_BYTES               | UInt32BE |     4|
|LUKS_MK_DIGEST               | chars    |    20|
|LUKS_MK_DIGEST_SALT          | chars    |    32|
|LUKS_MK_DIGEST_ITER          | UInt32BE |     4|
|LUKS_UUID                    | charsnt  |    40|
+-----------------------------+----------+------+
|KEYBLOCK_ACTIVE              | UInt32BE |     4|
|KEYBLOCK_PWD_ITER            | UInt32BE |     4|
|KEYBLOCK_PWD_SALT            | chars    |    32|
|KEYBLOCK_KEY_MATERIAL_OFFSET | UInt32BE |     4|
|KEYBLOCK_STRIPES             | UInt32BE |     4|
+-----------------------------+----------+------+
| KEYBLOCKS ...               |          |      |
+-----------------------------+----------+------+
| KEY MATERIALS ...           |          |      |
+-----------------------------+----------+------+

chars         : byte array
charsnt       : null terminated byte array
UInt16BE      : 16 bits big endian unsigned int
UInt32BE      : 32 bits big endian unsigned int
KEYBLOCKS     : the remaining keyblocks if more than one
KEY MATERIALS : KEYBLOCK_KEY_MATERIAL_OFFSET marks the beginning of a key material in sector counts aligned to the sectorsize and keyslot alignment
```

## Function Reference (cont.)

#### <a id="constructor"></a> constructor([[options](#options) : _Object_])
```javascript
/**
 * LUKS Constructor
 * @param {Object} [options] see customizable variables
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS();
```

#### <a id="createluksheaderwithmasterkey"></a> createLUKSHeaderWithMasterKey(masterKey : [_Buffer_](https://nodejs.org/api/buffer.html) [,[options](#options) : _Object_]) : [_Buffer_](https://nodejs.org/api/buffer.html)
```javascript
/**
 * Generates a new LUKS header using a masterKey
 * @param {Buffer} masterKey the length of the key should make sense for the chosen cipher mode
 * @param {Object} [options] options to use during header creation
 * @returns {Buffer} the generated luks header
 */
```
##### Example:
```javascript
const Crypto = require('crypto');
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var masterKey = Crypto.randomBytes(32); // using the default aes-128-xts cipher
var luksHeader = luks.createLUKSHeaderWithMasterKey(masterKey);
```

#### <a id="createluksheader"></a> createLUKSHeader(passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : [_Buffer_](https://nodejs.org/api/buffer.html)
```javascript
/**
 * Creates a luks header initialized with a passKey
 * @param {Buffer|String} passKey used to decrypt the master key
 * @param {Object} [options] options to use during header creation
 * @returns {Buffer} the luks header
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
```

#### <a id="getluksheaderinfo"></a> getLUKSHeaderInfo(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html)) : _Object_
```javascript
/**
 * Parses a LUKS header for its information
 * @param {Buffer} luksHeader to fetch information for
 * @returns {Object} header information
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var info = luks.getLUKSHeaderInfo(luksHeader);
```

#### <a id="getlukskeyslotindex"></a> getLUKSKeyslotIndex(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : _Number_
```javascript
/**
 * Fetches the keyslot index that matches the passKey
 * If multiple keyslots use the same passKey, then the first one to match will be returned
 * @param {Buffer} luksHeader the complete luks header
 * @param {Buffer|String} passKey the passKey to search a matching keyslot for
 * @param {Object} [options] options to use during keyslot search
 * @returns {Number} an index >0 if found, -1 if not
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var index = luks.getLUKSKeyslotIndex(luksHeader,passKey);
```

#### <a id="getluksmasterkey"></a> getLUKSMasterKey(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_] : _Object_]) : [_Buffer_](https://nodejs.org/api/buffer.html)
```javascript
/**
 * Recover the masterkey using a passkey
 * @param {Buffer} luksHeader
 * @param {Buffer|String} passKey to unlock one of the keyslots
 * @param {Object} [options] options to supply to the function
 * @returns {Buffer} the masterkey or null if passkey did not match any stored key
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var masterKey = luks.getLUKSMasterKey(luksHeader,passKey);
```

#### <a id="addlukskeywithmasterkey"></a> addLUKSKeyWithMasterKey(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), masterKey : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : _Number_
```javascript
/**
 * Adds a new LUKS key to the header
 * @param {Buffer} luksHeader the complete buffer containing the header
 * @param {Buffer} masterKey the master key
 * @param {Buffer|String} passKey the passkey to unlock the master key
 * @param {Object} [options] options to supply to the function
 * @returns {Number} The keyslot the passKey has been added to
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var masterKey = luks.getLUKSMasterKey(luksHeader,passKey);
var anotherPassKey = 'anothersecretpassword';
var index = luks.addLUKSKeyWithMasterKey(luksHeader,masterKey,anotherPassKey);
```

#### <a id="addlukskey"></a> addLUKSKey(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), existingPassKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_, newPassKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : _Number_
```javascript
/**
 * Adds a new passKey to a luks header using an existing passKey
 * @param {Buffer} luksHeader the luks header
 * @param {Buffer|String} existingPassKey existing passKey to unlock masterkey
 * @param {Buffer|String} newPassKey the new key to add to an available keyblock
 * @param {Object} [options] options to use during key insertion
 * @returns {Number} The keyslot the passKey has been added to
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var anotherPassKey = 'anothersecretpassword';
var index = luks.addLUKSKey(luksHeader,passKey,anotherPassKey);
```

#### <a id="removelukskey"></a> removeLUKSKey(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), index : _Number_ [,[options](#options) : _Object_]) : _void_
```javascript
/**
 * Removes the passKey at index setting the keyblock to disabled
 * @param {Buffer} luksHeader the luks header
 * @param {Number} index index starting at 0 should not go over the maximum amount of keyslots
 * @param {Object} [options] options to use during key removal
 */
```
##### Example:
```javascript
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var anotherPassKey = 'anothersecretpassword';
var index = luks.addLUKSKey(luksHeader,passKey,anotherPassKey);
luks.removeLUKSKey(luksHeader,0);
```

#### <a id="encryptlukswithmasterkey"></a> encryptLUKSWithMasterKey(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), masterKey : [_Buffer_](https://nodejs.org/api/buffer.html) [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)
```javascript
/**
 * Creates a duplex stream in which you write unencrypted data and read encrypted data
 * @param {Buffer} luksHeader the luks header
 * @param {Buffer} masterKey used to encrypt the data
 * @param {Object} [options] options to use during encryption
 * @returns {stream.Duplex}
 */
```
##### Example:
```javascript
const FS = require('fs');
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var masterKey = luks.getLUKSMasterKey(luksHeader,passKey);
FS.createReadStream('unencryptedfile')
.pipe(luks.encryptLUKSWithMasterKey(luksHeader,masterKey))
.pipe(FS.createWriteStream('encryptedfile'));
```

#### <a id="encryptluks"></a> encryptLUKS(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)
```javascript
/**
 * Creates a duplex stream in which you write unencrypted data and read encrypted data
 * @param {Buffer} luksHeader the luks header
 * @param {Buffer|String} passKey passkey to decrypt masterkey
 * @param {Object} [options] options to use during encryption
 * @returns {stream.Duplex}
 */
```
##### Example:
```javascript
const FS = require('fs');
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
FS.createReadStream('unencryptedfile')
.pipe(luks.encryptLUKS(luksHeader,passKey))
.pipe(FS.createWriteStream('encryptedfile'));
```

#### <a id="decryptlukswithmasterkey"></a> decryptLUKSWithMasterKey(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), masterKey : [_Buffer_](https://nodejs.org/api/buffer.html) [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)
```javascript
/**
 * Creates a duplex stream in which you write encrypted data and read unencrypted data
 * @param {Buffer} luksHeader the luks header
 * @param {Buffer} masterKey masterKey to decrypt data
 * @param {Object} [options] options to use during encryption
 * @returns {stream.Duplex}
 */
```
##### Example:
```javascript
const FS = require('fs');
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
var masterKey = luks.getLUKSMasterKey(luksHeader,passKey);
FS.createReadStream('encryptedfile')
.pipe(luks.decryptLUKSWithMasterKey(luksHeader,masterKey))
.pipe(FS.createWriteStream('unencryptedfile'));
```

#### <a id="decryptluks"></a> decryptLUKS(luksHeader : [_Buffer_](https://nodejs.org/api/buffer.html), passKey : _[Buffer](https://nodejs.org/api/buffer.html)|String_ [,[options](#options) : _Object_]) : [_stream.Duplex_](https://nodejs.org/api/stream.html#stream_class_stream_duplex)
```javascript
/**
 * Creates a duplex stream in which you write encrypted data and read unencrypted data
 * @param {Buffer} luksHeader the luks header
 * @param {Buffer|String} passKey passkey to decrypt masterkey
 * @param {Object} [options] options to use during encryption
 * @returns {stream.Duplex}
 */
```
##### Example:
```javascript
const FS = require('fs');
const LUKS = require('node-luks');
var luks = new LUKS(); // use default options
var passKey = 'verysecretpassword';
var luksHeader = luks.createLUKSHeader(passKey);
FS.createReadStream('encryptedfile')
.pipe(luks.decryptLUKS(luksHeader,passKey))
.pipe(FS.createWriteStream('unencryptedfile'));
```
