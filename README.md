# LUKS for nodejs

```
var LUKS = require('node-luks');
var luks = new LUKS([options : Object]) : Class;

/* Header creation */
luks.createLUKSHeaderWithMasterKey(masterKey : Buffer [,options : Object]) : Buffer;
luks.createLUKSHeader(passKey : Buffer|String [,options : Object]) : Buffer;

/* Header information */
luks.getLUKSHeaderInfo(luksHeader : Buffer) : Object;
luks.getLUKSKeyslotIndex(luksHeader : Buffer, passKey : Buffer|String [,options : Object]) : Number;
luks.getLUKSMasterKey(luksHeader : Buffer, passKey : Buffer|String [,options]) : Buffer;

/* Modify passkeys */
luks.addLUKSKeyWithMasterKey(luksHeader : Buffer, masterKey : Buffer, passKey : Buffer|String [,options : Object]) : Number;
luks.addLUKSKey(luksHeader : Buffer, existingPassKey : Buffer|String, newPassKey : Buffer|String [,options : Object]) : Number;
luks.removeLUKSKey(luksHeader : Buffer, index : Number [,options : Object]) : void;

/* Data encryption/decryption */
luks.encryptLUKSWithMasterKey(luksHeader : Buffer, masterKey : Buffer [,options : Object]) : stream.Duplex;
luks.encryptLUKS(luksHeader : Buffer, passKey : Buffer|String [,options : Object]) : stream.Duplex;
luks.decryptLUKSWithMasterKey(luksHeader : Buffer, masterKey : Buffer [,options : Object]) : stream.Duplex;
luks.decryptLUKS(luksHeader : Buffer, passKey : Buffer|String [,options : Object]) : stream.Duplex;
```

## Default options
```
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

## Options for web oriented applications
```
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
