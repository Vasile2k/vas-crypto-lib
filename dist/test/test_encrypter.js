"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("assert");
const data_encrypter_1 = require("../data_encrypter");
const encryption_1 = require("../encryption");
describe("encrypter", () => {
    it("should encrypt and decrypt a big blob in ECB", () => {
        let textEncoder = new TextEncoder();
        let blob = textEncoder.encode("afara ploo cal uaie cazan pedale gigel vasilica Cadavru frumos urat se poate nu se poate da");
        let key = textEncoder.encode("uaieccaluaieccal");
        let enc = new data_encrypter_1.DataEncrypter();
        enc.setModeOfOperation(data_encrypter_1.ModeOfOperation.ECB);
        enc.setEncryptionAlgorithm(new encryption_1.RC6EncryptionAlgorithm());
        let encrypted = enc.encryptBlob(blob, key);
        let decrypted = enc.decryptBlob(encrypted, key);
        // length is not important since the blob will be padded
        blob.forEach((val, i) => {
            assert_1.strict.equal(val, decrypted[i], "Decrypted doesn't match plaintext.");
        });
    });
    it("should encrypt and decrypt a big blob in CBC", () => {
        let textEncoder = new TextEncoder();
        let blob = textEncoder.encode("afara ploo cal uaie cazan pedale gigel vasilica Cadavru frumos urat se poate nu se poate da");
        let key = textEncoder.encode("uaieccaluaieccal");
        let enc = new data_encrypter_1.DataEncrypter();
        enc.setModeOfOperation(data_encrypter_1.ModeOfOperation.CBC);
        enc.setEncryptionAlgorithm(new encryption_1.RC6EncryptionAlgorithm());
        enc.setInitializationVector(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));
        let encrypted = enc.encryptBlob(blob, key);
        let decrypted = enc.decryptBlob(encrypted, key);
        // length is not important since the blob will be padded
        blob.forEach((val, i) => {
            assert_1.strict.equal(val, decrypted[i], "Decrypted doesn't match plaintext.");
        });
    });
});
//# sourceMappingURL=test_encrypter.js.map