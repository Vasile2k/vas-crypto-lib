# vas-crypto-lib
Small JS library for crypto

## Features
This library supports the following symmetric encryption algorithms:
* RC6
* RC4

This library supports the following block cipher modes of operation:
* ECB
* CBC

## Installation
Via `npm`:
```
> npm install vas-crypto-lib
```

## Usage
```ts
import { ModeOfOperation, DataEncrypter, RC6EncryptionAlgorithm, RC4EncryptionAlgorithm } from "vas-crypto-lib";

let textEncoder = new TextEncoder();

let blob = textEncoder.encode("Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.");
let key = textEncoder.encode("super_secret_key");

let enc = new DataEncrypter();
enc.setModeOfOperation(ModeOfOperation.CBC);
enc.setEncryptionAlgorithm(new RC6EncryptionAlgorithm());
enc.setInitializationVector(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));

let encrypted = enc.encryptBlob(blob, key);

// Do something with the encrypted data

let decrypted = enc.decryptBlob(encrypted, key);

// Do something with the decrypted data
```

## License

 * This thing is distributed under Apache 2.0. See [LICENSE](LICENSE).

## Additional details

### Contact

You can find me [here][1] to ask questions.

[1]: https://github.com/Vasile2k