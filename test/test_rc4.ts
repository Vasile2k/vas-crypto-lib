import { strict as assert } from "assert";

import { RC4EncryptionAlgorithm } from "../encryption";

describe("rc4-encryption", () => {

    it("should pass this test", () => {
        assert(true);
    });

    it("should encrypt and decrypt the plaintext", () => {
        let textEncoder = new TextEncoder();

        let plainText = textEncoder.encode("uaiecalcazan");
        let key = textEncoder.encode("oaeeoaee");

        let enc = new RC4EncryptionAlgorithm();

        let encrypted = enc.encryptBlock(plainText, key);

        let decrypted = enc.decryptBlock(encrypted, key);

        assert.equal(decrypted.length, plainText.length, "Decrypted length doesn't match plaintext length.");

        decrypted.forEach((val, i) => {
            assert.equal(val, plainText[i], "Decrypted doesn't match plaintext.");
        });
    });

    it("should match test vectors", () => {
        let testVectors = [
            {
                "plaintext": "Plaintext",
                "key": "Key",
                "ciphertext": "BB F3 16 E8 D9 40 AF 0A D3"
            },
            {
                "plaintext": "pedia",
                "key": "Wiki",
                "ciphertext": "10 21 BF 04 20"
            },
            {
                "plaintext": "Attack at dawn",
                "key": "Secret",
                "ciphertext": "45 A0 1F 64 5F C3 5B 38 35 52 54 4B 9B F5"
            }
        ];

        testVectors.forEach(testVector => {
            let uint8ArrayFromHexStrng = (str: string) => {
                let arr: number[] = [];
                str.split(" ").forEach(val => {
                    arr.push(parseInt(val, 16));
                });
                return new Uint8Array(arr);
            };
            let textEncoder = new TextEncoder();

            let enc = new RC4EncryptionAlgorithm();
            let text = textEncoder.encode(testVector["plaintext"]);
            let key = textEncoder.encode(testVector["key"]);
            let cipher = uint8ArrayFromHexStrng(testVector["ciphertext"]);

            let encrypted = enc.encryptBlock(text, key);

            assert.equal(encrypted.length, cipher.length, "Ciphertext length mismatch.");
            encrypted.forEach((val, i) => {
                assert.equal(val, cipher[i], "Ciphertext mismatch.");
            });

            let decrypted = enc.decryptBlock(encrypted, key);

            assert.equal(decrypted.length, text.length, "Decrypted length doesn't match plaintext length.");
            decrypted.forEach((val, i) => {
                assert.equal(val, text[i], "Decrypted doesn't match plaintext.");
            });

        });

        assert(true);
    });

});