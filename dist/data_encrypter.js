"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DataEncrypter = exports.ModeOfOperation = void 0;
const helper_1 = require("./helper");
var ModeOfOperation;
(function (ModeOfOperation) {
    ModeOfOperation[ModeOfOperation["ECB"] = 0] = "ECB";
    ModeOfOperation[ModeOfOperation["CBC"] = 1] = "CBC";
})(ModeOfOperation || (ModeOfOperation = {}));
exports.ModeOfOperation = ModeOfOperation;
class DataEncrypter {
    constructor() {
        this.enc = undefined;
        this.modeOfOperation = undefined;
        this.initializationVector = undefined;
    }
    setEncryptionAlgorithm(enc) {
        this.enc = enc;
    }
    getEncryptionAlgorithm() {
        return this.enc;
    }
    setModeOfOperation(mode) {
        this.modeOfOperation = mode;
    }
    getModeOfOperation() {
        return this.modeOfOperation;
    }
    setInitializationVector(iv) {
        // Make a copy of iv so it can't be changed later
        this.initializationVector = new Uint8Array(iv);
    }
    getInitializationVector() {
        return this.initializationVector;
    }
    encryptBlob(input, key) {
        if (input.length === 0) {
            return input;
        }
        if (this.enc === undefined) {
            throw new Error("Encryption algorithm not set!");
        }
        if (this.modeOfOperation === undefined) {
            throw new Error("Mode of operation not set!");
        }
        let chunks = [];
        let supportedBlockSize = this.enc.getBlockSizes();
        if (typeof supportedBlockSize === "string" && supportedBlockSize === "any") {
            return this.enc.encryptBlock(input, key);
        }
        else if (typeof supportedBlockSize === "object") {
            let blockSize = supportedBlockSize[0] / 8;
            for (let i = 0; i < input.length; i += blockSize) {
                let chunk = new Uint8Array(input.slice(i, i + blockSize));
                if (chunk.length !== blockSize) {
                    // pad last block
                    let paddedBlock = new Uint8Array(blockSize);
                    paddedBlock.fill(0);
                    for (let j = 0; j < chunk.length; ++j) {
                        paddedBlock[j] = chunk[j];
                    }
                    chunk = paddedBlock;
                }
                chunks.push(chunk);
            }
            let encrypted = [];
            if (this.modeOfOperation == ModeOfOperation.ECB) {
                for (let chunk of chunks) {
                    this.enc.encryptBlock(chunk, key).forEach(b => encrypted.push(b));
                }
            }
            else if (this.modeOfOperation == ModeOfOperation.CBC) {
                if (this.initializationVector == null || this.initializationVector.length !== blockSize) {
                    throw new Error("Initialization vector is of wrong size!");
                }
                let blocks = [];
                blocks.push(this.enc.encryptBlock(helper_1.xor(chunks[0], this.initializationVector), key));
                for (let i = 1; i < chunks.length; ++i) {
                    blocks.push(this.enc.encryptBlock(helper_1.xor(chunks[i], blocks[i - 1]), key));
                }
                for (let block of blocks) {
                    block.forEach(b => encrypted.push(b));
                }
            }
            return new Uint8Array(encrypted);
        }
        return new Uint8Array(0);
    }
    decryptBlob(input, key) {
        if (input.length == 0) {
            return input;
        }
        if (this.enc == null) {
            throw new Error("Encryption algorithm not set!");
        }
        if (this.modeOfOperation == null) {
            throw new Error("Mode of operation not set!");
        }
        let supportedBlockSize = this.enc.getBlockSizes();
        if (typeof supportedBlockSize === "string" && supportedBlockSize === "any") {
            return this.enc.encryptBlock(input, key);
        }
        else if (typeof supportedBlockSize === "object") {
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
            if (this.modeOfOperation == ModeOfOperation.ECB) {
                for (let chunk of chunks) {
                    this.enc.decryptBlock(chunk, key).forEach(b => decrypted.push(b));
                }
            }
            else if (this.modeOfOperation == ModeOfOperation.CBC) {
                if (this.initializationVector !== undefined && this.initializationVector.length != blockSize) {
                    throw new Error("Initialization vector is of wrong size!");
                }
                let blocks = [];
                blocks.push(helper_1.xor(this.enc.decryptBlock(chunks[0], key), this.initializationVector));
                for (let i = 1; i < chunks.length; ++i) {
                    blocks.push(helper_1.xor(this.enc.decryptBlock(chunks[i], key), blocks[i - 1]));
                }
                for (let block of blocks) {
                    block.forEach(b => decrypted.push(b));
                }
            }
            return new Uint8Array(decrypted);
        }
        return new Uint8Array(0);
    }
}
exports.DataEncrypter = DataEncrypter;
//# sourceMappingURL=data_encrypter.js.map