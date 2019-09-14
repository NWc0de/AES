# Java AES

This repository is home to an implementation of the AES (Rijndael) cipher in Java. 
The suite of methods and ultimate cipher function were tested with example vectors 
provided by [NIST FISP-197](https://www.nist.gov/publications/advanced-encryption-standard-aes) 
 and [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 to prove compliance with NIST specification (CipherTests.java and CounterModeTests.java).    

## Usage

```bash
java AES -k <keyfile> -o <output file> -f <input file> -v <IV file> -d <optional: decryption> -CTR <optional: counter mode>
```

An Initialization Vector is required to run the program because the default mode is CBC (Cipher Block Chaining).
16 byte IVs can be generated with

```bash
dd if=/dev/urandom of=initvector bs=4 count=4
```

## Initial Counter Blocks
Any mode of generation is acceptable for ICBs however the ICB should 
be unique for each message/file. A single ICB can be used for up to 2^m blocks of plaintext, where m is the
number of bits used to form an integer in the standard incrementation function. In this implementation m=32 
so a new ICB must be generated for every 64 gigabytes of plaintext that is processed.

**Note:** In CTR mode the IV corresponds to the initial counter block (ICB).

## Initialization Vectors
In CBC mode the initialization vector (IV) does not need to be secret. It may be transmitted
in plaintext along with the ciphertext. However, the IV must be unique across invocations
of the cipher (ie. for each file/message that is encrypted, a unique, unpredictable IV should be 
generated.) This process should use a secure random number generator to produce IVs.

More information about ICBs, IVs, and AES modes can be found in 
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)