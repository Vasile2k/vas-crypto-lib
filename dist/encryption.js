"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RC4EncryptionAlgorithm = exports.RC6EncryptionAlgorithm = exports.EncryptionAlgorithm = void 0;
const helper_1 = require("./helper");
class EncryptionAlgorithm {
}
exports.EncryptionAlgorithm = EncryptionAlgorithm;
class RC6EncryptionAlgorithm extends EncryptionAlgorithm {
    /**
     * Class constructor
     * @param rounds optional parameter; can be set later; defaults to 20
     */
    constructor(rounds) {
        super();
        this.rounds = rounds || 20;
    }
    getName() {
        return "RC6";
    }
    getBlockSizes() {
        return [128];
    }
    getKeySizes() {
        return [128, 192, 256];
    }
    setRounds(rounds) {
        this.rounds = rounds;
    }
    getRounds() {
        return this.rounds;
    }
    /**
     * RC6 key schedule
     * @param key - key bytes
     * @return array of 32-bit keys
     */
    rc6KeySchedule(key) {
        if (this.getKeySizes().indexOf(key.length * 8) === -1) {
            throw new Error("Invalid key size!");
        }
        // Copy key to prevent fucking it
        let keyCopy = new Uint8Array(key);
        let L = new Uint32Array(keyCopy.buffer);
        let c = L.length;
        let r = this.getRounds();
        let P32 = 0xB7E15163;
        let Q32 = 0x9E3779B9;
        let S = new Uint32Array(2 * r + 4);
        S[0] = P32;
        for (let i = 1; i < 2 * r + 4; ++i) {
            S[i] = S[i - 1] + Q32;
        }
        let A = new Uint32Array(1);
        let B = new Uint32Array(1);
        let i = 0;
        let j = 0;
        let v = 3 * Math.max(c, 2 * r + 4);
        for (let s = 0; s < v; ++s) {
            A[0] = helper_1.rotateLeftInt32((S[i] + A[0] + B[0]), 3);
            S[i] = A[0];
            B[0] = helper_1.rotateLeftInt32((L[j] + A[0] + B[0]), (A[0] + B[0]));
            L[j] = B[0];
            i = (i + 1) % (2 * r + 4);
            j = (j + 1) % c;
        }
        return S;
    }
    encryptBlock(input, key) {
        if (this.getBlockSizes().indexOf(input.length * 8) === -1) {
            throw new Error("Invalid input block size!");
        }
        let S = this.rc6KeySchedule(key);
        let ABCD = new Uint32Array(input.buffer);
        let A = ABCD[0];
        let B = ABCD[1];
        let C = ABCD[2];
        let D = ABCD[3];
        // let int32 = n => n & 0xFFFFFFFF;
        // Use BigInt everywhere because some weird bullshit happens otherwise
        // Javascript's big number are double or float or some fucking kind of
        // shit which is approximate and not exact... and this fucks the entire
        // algorithm, so that's why I have to use big int
        // my dick...
        let int32 = (n) => Number(n % BigInt(0x100000000));
        B = int32(BigInt(B + S[0]));
        D = int32(BigInt(D + S[1]));
        for (let i = 1; i <= this.rounds; ++i) {
            let lgw = 5; // log2 of word size in bits(32)
            // That's a multiplication of 2 very big numbers
            // Overflows from 32-bit and JS automatically converts it to double
            // Double my dick
            // By using BigInt the multiplication is correct and I can do that
            //     because I chop first few bits anyway
            let t = helper_1.rotateLeftInt32(int32(BigInt(B) * BigInt(2 * B + 1)), lgw);
            let u = helper_1.rotateLeftInt32(int32(BigInt(D) * BigInt(2 * D + 1)), lgw);
            A = int32(BigInt(helper_1.rotateLeftInt32(A ^ t, u)) + BigInt(S[2 * i]));
            C = int32(BigInt(helper_1.rotateLeftInt32(C ^ u, t)) + BigInt(S[2 * i + 1]));
            [A, B, C, D] = [B, C, D, A];
        }
        A = int32(BigInt(A) + BigInt(S[2 * this.rounds + 2]));
        C = int32(BigInt(C) + BigInt(S[2 * this.rounds + 3]));
        let result = new Uint32Array(4);
        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;
        return new Uint8Array(result.buffer);
    }
    decryptBlock(input, key) {
        if (this.getBlockSizes().indexOf(input.length * 8) === -1) {
            throw new Error("Invalid encrypted block size!");
        }
        let S = this.rc6KeySchedule(key);
        let ABCD = new Uint32Array(input.buffer);
        let A = ABCD[0];
        let B = ABCD[1];
        let C = ABCD[2];
        let D = ABCD[3];
        // See #encryptBlock for detailed comments about BigInt
        let int32 = (n) => Number(n % BigInt(0x100000000));
        C = int32(BigInt(C - S[2 * this.rounds + 3]));
        A = int32(BigInt(A - S[2 * this.rounds + 2]));
        for (let i = this.rounds; i > 0; --i) {
            [A, B, C, D] = [D, A, B, C];
            let lgw = 5; // log2 of word size in bits(32)
            let u = helper_1.rotateLeftInt32(int32(BigInt(D) * BigInt(2 * D + 1)), lgw);
            let t = helper_1.rotateLeftInt32(int32(BigInt(B) * BigInt(2 * B + 1)), lgw);
            C = helper_1.rotateRightInt32(int32(BigInt(C - S[2 * i + 1])), t) ^ u;
            A = helper_1.rotateRightInt32(int32(BigInt(A - S[2 * i])), u) ^ t;
        }
        D = int32(BigInt(D - S[1]));
        B = int32(BigInt(B - S[0]));
        let result = new Uint32Array(4);
        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;
        return new Uint8Array(result.buffer);
    }
}
exports.RC6EncryptionAlgorithm = RC6EncryptionAlgorithm;
class RC4EncryptionAlgorithm extends EncryptionAlgorithm {
    constructor() {
        super();
    }
    getName() {
        return "RC4";
    }
    getBlockSizes() {
        return "any";
    }
    getKeySizes() {
        let keySizes = [];
        for (let keySize = 1; keySize <= 256; ++keySize) {
            keySizes.push(keySize);
        }
        return keySizes;
    }
    /**
     * Checks if a given key size is valid, since there are a lot of possibilities and generating a list with all of them is inefficient
     * @param keySize
     */
    isValidKeySize(keySize) {
        return keySize >= 1 && keySize <= 256;
    }
    /**
     * RC4 key schedule
     */
    rc4KeySchedule(key) {
        if (!this.isValidKeySize(key.length)) {
            throw new Error("Invalid key size!");
        }
        if (key.length < 5 || key.length > 16) {
            // Not the best idea to use console in a module but who cares?
            // console.warn("Key is of an unrecommended size");
        }
        // Initialization
        let n = 8;
        let s = new Uint32Array(1 << n);
        for (let i = 0; i < 1 << n; ++i) {
            s[i] = i;
        }
        let j = 0;
        // Scrambling
        for (let i = 0; i < 1 << n; ++i) {
            j = (j + s[i] + key[i % key.length]) % (1 << n);
            [s[i], s[j]] = [s[j], s[i]];
            // let tmp = s[i];
            // s[i] = s[j];
            // s[j] = tmp;
        }
        return s;
    }
    rc4PseudoRandomKeystream(s, length) {
        // Initialization
        let i = 0;
        let j = 0;
        let k = new Uint8Array(length);
        let n = 8;
        let mod = 1 << n;
        let z = 0;
        // Generation loop
        while (z < length) {
            i = (i + 1) % mod;
            j = (j + s[i]) % mod;
            [s[i], s[j]] = [s[j], s[i]];
            k[z++] = s[(s[i] + s[j]) % mod];
        }
        return k;
    }
    encryptBlock(input, key) {
        let s = this.rc4KeySchedule(key);
        let keystream = this.rc4PseudoRandomKeystream(s, input.length);
        let encrypted = new Uint8Array(input.length);
        for (let i = 0; i < input.length; ++i) {
            encrypted[i] = input[i] ^ keystream[i];
        }
        return encrypted;
    }
    decryptBlock(input, key) {
        // since the encryption is just a xor, if we xor
        // it again it should be decrypted
        return this.encryptBlock(input, key);
    }
}
exports.RC4EncryptionAlgorithm = RC4EncryptionAlgorithm;
//# sourceMappingURL=encryption.js.map