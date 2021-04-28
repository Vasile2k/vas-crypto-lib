import { EncryptionAlgorithm, RC6EncryptionAlgorithm } from "./encryption";

export {
    EncryptionAlgorithm,
    RC6EncryptionAlgorithm
};

/*function rc6EncryptBlob(input: Uint8Array, key: Uint8Array): Uint8Array{
    let rc6 = new RC6EncryptionAlgorithm();
    let chunks = [];
    let blockSize = rc6.getBlockSizes()[0] / 8;
    for(let i = 0; i < input.length; i += blockSize){
        let chunk = new Uint8Array(input.slice(i, i + blockSize));
        if(chunk.length !== blockSize){
            // pad last block
            let paddedBlock = new Uint8Array(blockSize);
            paddedBlock.fill(0);
            for(let j = 0; j < chunk.length; ++j){
                paddedBlock[j] = chunk[j];
            }
            chunk = paddedBlock;
        }
        chunks.push(chunk);
    }
    let encrypted = [];
    for (let chunk of chunks) {
        rc6.encryptBlock(chunk, key).forEach(b => encrypted.push(b));
    }
    return new Uint8Array(encrypted);
}

function rc6DecryptBlob(input: Uint8Array, key: Uint8Array): Uint8Array{
    let rc6 = new RC6EncryptionAlgorithm();
    let blockSize = rc6.getBlockSizes()[0] / 8;
    if(input.length % blockSize !== 0){
        throw new Error("Blob size can't be split in chunks!");
    }

    let chunks = [];

    for(let i = 0; i < input.length; i += blockSize){
        let chunk = new Uint8Array(input.slice(i, i + blockSize));
        chunks.push(chunk);
    }
    let encrypted = [];
    for (let chunk of chunks) {
        rc6.encryptBlock(chunk, key).forEach(b => encrypted.push(b));
    }
    return new Uint8Array(encrypted);
}

console.log("cal");

let textEncoder = new TextEncoder();
let textDecoder = new TextDecoder();
let text = "uaieuaieuaieuaie";
let key = "uaieuaieuaieuaie";
// let text = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
// let key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

let enc = new RC6EncryptionAlgorithm();

let result = enc.encryptBlock(textEncoder.encode(text), textEncoder.encode(key));

let dec = enc.decryptBlock(result, textEncoder.encode(key));

console.log(result);
console.log(textDecoder.decode(dec));

let resultString = "";
result.forEach(k => resultString += k.toString(16) + " ");
console.log(resultString);*/

/*
let fileBytes = readFileSync("./text.txt");

let encryptedFile = rc6EncryptBlob(fileBytes, textEncoder.encode(key));
let decryptedFile = rc6DecryptBlob(encryptedFile, textEncoder.encode(key));

console.log(textDecoder.decode(fileBytes));
console.log(textDecoder.decode(encryptedFile));
console.log(textDecoder.decode(decryptedFile));*/
