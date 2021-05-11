import { EncryptionAlgorithm } from "./encryption";
import { xor } from "./helper";


enum ModeOfOperation {
    "ECB",
    "CBC"
}

class DataEncrypter {
    private enc: EncryptionAlgorithm;
    private modeOfOperation: ModeOfOperation;
    private initializationVector: Uint8Array;

    constructor() {
        this.enc = null;
        this.modeOfOperation = null;
        this.initializationVector = null;
    }

    setEncryptionAlgorithm(enc: EncryptionAlgorithm): void{
        this.enc = enc;
    }

    getEncryptionAlgorithm(): EncryptionAlgorithm{
        return this.enc;
    }

    setModeOfOperation(mode: ModeOfOperation): void{
        this.modeOfOperation = mode;
    }

    getModeOfOperation(): ModeOfOperation{
        return this.modeOfOperation;
    }

    setInitializationVector(iv: Uint8Array): void{
        // Make a copy of iv so it can't be changed later
        this.initializationVector = new Uint8Array(iv);
    }

    getInitializationVector(): Uint8Array{
        return this.initializationVector;
    }

    encryptBlob(input: Uint8Array, key: Uint8Array): Uint8Array{
        if(input.length == 0){
            return input;
        }
        if(this.enc == null){
            throw new Error("Encryption algorithm not set!");
        }
        if(this.modeOfOperation == null){
            throw new Error("Mode of operation not set!");
        }
        let chunks = [];
        let supportedBlockSize = this.enc.getBlockSizes();
        if(typeof supportedBlockSize === "string" && supportedBlockSize === "any"){
            return this.enc.encryptBlock(input, key);
        }else if(typeof supportedBlockSize === "object"){
            let blockSize = supportedBlockSize[0] / 8;
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
            if(this.modeOfOperation == ModeOfOperation.ECB){
                for (let chunk of chunks) {
                    this.enc.encryptBlock(chunk, key).forEach(b => encrypted.push(b));
                }
            }else if(this.modeOfOperation == ModeOfOperation.CBC){
                if(this.initializationVector == null || this.initializationVector.length !== blockSize){
                    throw new Error("Initialization vector is of wrong size!");
                }
                let blocks = [];
                blocks.push(this.enc.encryptBlock(xor(chunks[0], this.initializationVector), key));
                for(let i = 1; i < chunks.length; ++i){
                    blocks.push(this.enc.encryptBlock(xor(chunks[i], blocks[i-1]), key));
                }
                for(let block of blocks){
                    block.forEach(b => encrypted.push(b));
                }
            }
            return new Uint8Array(encrypted);
        }
        return null;
    }

    decryptBlob(input: Uint8Array, key: Uint8Array): Uint8Array{
        if(input.length == 0){
            return input;
        }
        if(this.enc == null){
            throw new Error("Encryption algorithm not set!");
        }
        if(this.modeOfOperation == null){
            throw new Error("Mode of operation not set!");
        }
        let supportedBlockSize = this.enc.getBlockSizes();
        if(typeof supportedBlockSize === "string" && supportedBlockSize === "any"){
            return this.enc.encryptBlock(input, key);
        }else if(typeof supportedBlockSize === "object") {
            let blockSize = supportedBlockSize[0] / 8;
            if (input.length % blockSize !== 0) {
                throw new Error("Blob size can't be split in chunks!");
            }

            let chunks = [];

            for (let i = 0; i < input.length; i += blockSize) {
                let chunk = new Uint8Array(input.slice(i, i + blockSize));
                chunks.push(chunk);
            }
            let decrypted = [];
            if(this.modeOfOperation == ModeOfOperation.ECB){
                for (let chunk of chunks) {
                    this.enc.decryptBlock(chunk, key).forEach(b => decrypted.push(b));
                }
            }else if(this.modeOfOperation == ModeOfOperation.CBC) {
                if(this.initializationVector.length != blockSize){
                    throw new Error("Initialization vector is of wrong size!");
                }
                let blocks = [];
                blocks.push(xor(this.enc.decryptBlock(chunks[0], key), this.initializationVector));
                for(let i = 1; i < chunks.length; ++i){
                    blocks.push(xor(this.enc.decryptBlock(chunks[i], key), blocks[i-1]));
                }
                for(let block of blocks){
                    block.forEach(b => decrypted.push(b));
                }
            }
            return new Uint8Array(decrypted);
        }
        return null;
    }
}

export {
    ModeOfOperation, DataEncrypter
};
