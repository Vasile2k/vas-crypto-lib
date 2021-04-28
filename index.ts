import { Buffer } from "buffer";
import { readFileSync } from "fs";

const BLOCK_SIZES = [128];
const KEY_SIZES = [128, 192, 256];
const ROUNDS = 20;

function rotateLeftInt32(num: number, pos: number): number{
    pos %= 32;
    return ((num << pos) | (num >>> (32 - pos))) & (0xFFFFFFFF);
}

function rotateRightInt32(num: number, pos: number): number{
    pos %= 32;
    return ((num >>> pos) | (num << (32 - pos))) & (0xFFFFFFFF);
}

/**
 * RC6 key schedule
 * @param key - key bytes
 * @return array of 32-bit keys
 */
function rc6KeySchedule(key: Uint8Array): Uint32Array{
    if(KEY_SIZES.indexOf(key.length * 8) === -1){
        throw new Error("Invalid key size!");
    }
    let L = new Uint32Array(key.buffer);
    let c = L.length;
    let r = ROUNDS;
    let P32 = 0xB7E15163;
    let Q32 = 0x9E3779B9;

    let S = new Uint32Array(2*r + 4);
    S[0] = P32;

    for(let i = 1; i < 2*r + 4; ++i){
        S[i] = S[i-1] + Q32;
    }

    let A = new Uint32Array(1);
    let B = new Uint32Array(1);
    let i = 0;
    let j = 0;

    let v = 3 * Math.max(c, 2*r + 4);

    for(let s = 0; s < v; ++s){
        A[0] = rotateLeftInt32((S[i] + A[0] + B[0]), 3);
        S[i] = A[0];
        B[0] = rotateLeftInt32((L[j] + A[0] + B[0]), (A[0] + B[0]));
        L[j] = B[0];
        i = (i + 1) % (2 * r + 4);
        j = (j + 1) % c;
    }

    return S;
}

function rc6EncryptBlock(input: Uint8Array, key: Uint8Array): Uint8Array{
    if(BLOCK_SIZES.indexOf(input.length * 8) === -1){
        throw new Error("Invalid input block size!");
    }
    let S = rc6KeySchedule(key);
    let ABCD = new Uint32Array(input.buffer);
    let A = ABCD[0];
    let B = ABCD[1];
    let C = ABCD[2];
    let D = ABCD[3];

    let int32 = n => n & 0xFFFFFFFF;

    B = int32(B + S[0]);
    D = int32(D + S[1]);

    for(let i = 0; i < ROUNDS; ++i){
        let lgw = 5; // log2 of word size in bits(32)
        let t = rotateLeftInt32(int32(B * (2*B + 1)), lgw);
        let u = rotateLeftInt32(int32(D * (2*D + 1)), lgw);

        A = int32(rotateLeftInt32(A ^ t, u) + S[2*i]);
        C = int32(rotateLeftInt32(C ^ u, t) + S[2*i + 1]);

        [A, B, C, D] = [B, C, D, A];
    }

    A = int32(A + S[2*ROUNDS + 2]);
    C = int32(C + S[2*ROUNDS + 3]);

    let result = new Uint32Array(4);
    result[0] = A;
    result[1] = B;
    result[2] = C;
    result[3] = D;

    return new Uint8Array(result.buffer);
}

function rc6DecryptBlock(input: Uint8Array, key: Uint8Array): Uint8Array{
    if(BLOCK_SIZES.indexOf(input.length * 8) === -1){
        throw new Error("Invalid encrypted block size!");
    }
    let S = rc6KeySchedule(key);
    let ABCD = new Uint32Array(input.buffer);
    let A = ABCD[0];
    let B = ABCD[1];
    let C = ABCD[2];
    let D = ABCD[3];

    let int32 = n => n & 0xFFFFFFFF;


    C = int32(C - S[2*ROUNDS + 3]);
    A = int32(A - S[2*ROUNDS + 2]);

    for(let i = ROUNDS - 1; i >= 0; --i){
        [A, B, C, D] = [D, A, B, C];
        let lgw = 5; // log2 of word size in bits(32)

        let u = rotateLeftInt32(int32(D * (2*D + 1)), lgw);
        let t = rotateLeftInt32(int32(B * (2*B + 1)), lgw);

        C = rotateRightInt32(int32(C - S[2*i + 1]), t) ^ u;
        A = rotateRightInt32(int32(A - S[2*i]), u) ^ t;
    }

    D = int32(D - S[1]);
    B = int32(B - S[0]);

    let result = new Uint32Array(4);
    result[0] = A;
    result[1] = B;
    result[2] = C;
    result[3] = D;

    return new Uint8Array(result.buffer);
}

function rc6EncryptBlob(input: Uint8Array, key: Uint8Array): Uint8Array{
    let chunks = [];
    let blockSize = BLOCK_SIZES[0] / 8;
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
        rc6EncryptBlock(chunk, key).forEach(b => encrypted.push(b));
    }
    return new Uint8Array(encrypted);
}

function rc6DecryptBlob(input: Uint8Array, key: Uint8Array): Uint8Array{
    let blockSize = BLOCK_SIZES[0] / 8;
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
        rc6DecryptBlock(chunk, key).forEach(b => encrypted.push(b));
    }
    return new Uint8Array(encrypted);
}

console.log("cal");

let textEncoder = new TextEncoder();
let textDecoder = new TextDecoder();
let text = "uaieuaieuaieuaie";
let key = "uaieuaieuaieuaie";

let result = rc6EncryptBlock(textEncoder.encode(text), textEncoder.encode(key));

let resultString = "";
result.forEach(k => resultString += k.toString(16) + " ");
console.log(resultString);

let decrypted = rc6DecryptBlock(result, textEncoder.encode(key));

console.log(result);
console.log(Buffer.from(String.fromCharCode.apply(null, result)).toString("base64"));

console.log(textDecoder.decode(decrypted));


let fileBytes = readFileSync("./text.txt");

let encryptedFile = rc6EncryptBlob(fileBytes, textEncoder.encode(key));
let decryptedFile = rc6DecryptBlob(encryptedFile, textEncoder.encode(key));

console.log(textDecoder.decode(fileBytes));
console.log(textDecoder.decode(encryptedFile));
console.log(textDecoder.decode(decryptedFile));
