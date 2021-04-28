import { rotateLeftInt32, rotateRightInt32 } from "./helper";


abstract class EncryptionAlgorithm{
    /**
     * Algorithm name
     * @returns algorithm name
     */
    abstract getName(): string;

    /**
     * The possible sizes of blocks (in bits) of which algorithm can operate
     * @returns an array containing all possible block sizes
     */
    abstract getBlockSizes(): Array<number>;

    /**
     * The possible key sizes (in bits)
     * @returns an array containing all possible key sizes
     */
    abstract getKeySizes(): Array<number>;

    /**
     * Encrypts a block with the provided key
     * @param input the block to be encrypted
     * @param key the key to use for encryption
     * @returns the encrypted block
     */
    abstract encryptBlock(input: Uint8Array, key: Uint8Array): Uint8Array;

    /**
     * Decrypts a block with the provided key
     * @param input the block to be decrypted
     * @param key the key to use for decryption
     * @returns the decrypted block
     */
    abstract decryptBlock(input: Uint8Array, key: Uint8Array): Uint8Array;
}

class RC6EncryptionAlgorithm extends EncryptionAlgorithm {
    private rounds: number;

    /**
     * Class constructor
     * @param rounds optional parameter; can be set later; defaults to 20
     */
    constructor(rounds?: number) {
        super();
        this.rounds = rounds || 20;
    }

    getName(): string {
        return "RC6";
    }

    getBlockSizes(): Array<number> {
        return [128];
    }

    getKeySizes(): Array<number> {
        return [128, 192, 256];
    }

    setRounds(rounds: number) {
        this.rounds = rounds;
    }

    getRounds(): number {
        return this.rounds;
    }

    /**
     * RC6 key schedule
     * @param key - key bytes
     * @return array of 32-bit keys
     */
    rc6KeySchedule(key: Uint8Array): Uint32Array{
        if(this.getKeySizes().indexOf(key.length * 8) === -1){
            throw new Error("Invalid key size!");
        }
        let L = new Uint32Array(key.buffer);
        let c = L.length;
        let r = this.getRounds();
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

    encryptBlock(input: Uint8Array, key: Uint8Array): Uint8Array {
        if(this.getBlockSizes().indexOf(input.length * 8) === -1){
            throw new Error("Invalid input block size!");
        }
        let S = this.rc6KeySchedule(key);
        let ABCD = new Uint32Array(input.buffer);
        let A = ABCD[0];
        let B = ABCD[1];
        let C = ABCD[2];
        let D = ABCD[3];

        let int32 = n => n & 0xFFFFFFFF;

        B = int32(B + S[0]);
        D = int32(D + S[1]);

        for(let i = 0; i < this.rounds; ++i){
            let lgw = 5; // log2 of word size in bits(32)
            let t = rotateLeftInt32(int32(B * (2*B + 1)), lgw);
            let u = rotateLeftInt32(int32(D * (2*D + 1)), lgw);

            A = int32(rotateLeftInt32(A ^ t, u) + S[2*i]);
            C = int32(rotateLeftInt32(C ^ u, t) + S[2*i + 1]);

            [A, B, C, D] = [B, C, D, A];
        }

        A = int32(A + S[2*this.rounds + 2]);
        C = int32(C + S[2*this.rounds + 3]);

        let result = new Uint32Array(4);
        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;

        return new Uint8Array(result.buffer);
    }

    decryptBlock(input: Uint8Array, key: Uint8Array): Uint8Array {
        if(this.getBlockSizes().indexOf(input.length * 8) === -1){
            throw new Error("Invalid encrypted block size!");
        }
        let S = this.rc6KeySchedule(key);
        let ABCD = new Uint32Array(input.buffer);
        let A = ABCD[0];
        let B = ABCD[1];
        let C = ABCD[2];
        let D = ABCD[3];

        let int32 = n => n & 0xFFFFFFFF;


        C = int32(C - S[2*this.rounds + 3]);
        A = int32(A - S[2*this.rounds + 2]);

        for(let i = this.rounds - 1; i >= 0; --i){
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
}

export {
    EncryptionAlgorithm, RC6EncryptionAlgorithm
};
