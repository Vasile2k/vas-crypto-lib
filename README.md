# vas-crypto-lib
Small JS library for crypto

## Features
This library supports the following symmetric encryption algorithms:
* RC6
* RC4

This library supports the following block cipher modes of operation:
* ECB
* more to come...

## Installation
Via `npm`:
```
> npm install vas-crypto-lib
```

## Usage
```ts
import { RC6EncryptionAlgorithm, RC4EncryptionAlgorithm } from "vas-crypto-lib";

let textEncoder = new TextEncoder();
let textDecoder = new TextDecoder();
let text = "uaieuaieuaieuaie";
let key = "uaieuaieuaieuaie";

let rc6 = new RC6EncryptionAlgorithm();

let result = rc6.encryptBlock(textEncoder.encode(text), textEncoder.encode(key));

let dec = rc6.decryptBlock(result, textEncoder.encode(key));

console.log(result);
console.log(textDecoder.decode(dec));
```

## License

 * This thing is distributed under Apache 2.0. See [LICENSE](LICENSE).

## Additional details

### Contact

You can find me [here][1] to ask questions.

[1]: https://github.com/Vasile2k