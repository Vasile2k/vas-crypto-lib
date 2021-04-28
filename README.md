# vas-crypto-lib
Small JS library for crypto

## Features
This library supports the following symmetric encryption algorithms:
* RC6
* more to come...

This library supports the following cipher modes of operation:
* ECB
* more to come...

## Usage
```ts
import { RC6EncryptionAlgorithm } from "./encryption";

let textEncoder = new TextEncoder();
let textDecoder = new TextDecoder();
let text = "uaieuaieuaieuaie";
let key = "uaieuaieuaieuaie";

let enc = new RC6EncryptionAlgorithm();

let result = enc.encryptBlock(textEncoder.encode(text), textEncoder.encode(key));

let dec = enc.decryptBlock(result, textEncoder.encode(key));

console.log(result);
console.log(textDecoder.decode(dec));
```

## License

 * This thing is distributed under Apache 2.0. See [LICENSE](LICENSE).

## Additional details

### Contact

You can find me [here][1] to ask questions.

[1]: https://github.com/Vasile2k