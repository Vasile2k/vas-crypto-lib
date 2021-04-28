import { strict as assert } from "assert";

import { RC6EncryptionAlgorithm } from "../encryption";

describe("vas-crypto-lib", () => {

    it("should pass this test", () => {
        assert(true);
    });

    it("should encrypt and decrypt the plaintext", () => {
        let textEncoder = new TextEncoder();

        let plainText = textEncoder.encode("uaiecalcazanuoae");
        let key = textEncoder.encode("tigaeebataeekkal");

        let enc = new RC6EncryptionAlgorithm();

        let encrypted = enc.encryptBlock(plainText, key);

        let decrypted = enc.decryptBlock(encrypted, key);

        assert.equal(decrypted.length, plainText.length, "Decrypted length doesn't match plaintext length.");

        decrypted.every((val, i) => {
            assert.equal(val, plainText[i], "Decrypted doesn't match plaintext.");
        });
    });

    it("should match test vectors", () => {
        let testVectors = [
            {
                "plaintext": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "key": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "ciphertext": "8F C3 A5 36 56 B1 F7 78 C1 29 DF 4E 98 48 A4 1E"
            },
            {
                "plaintext": "02 13 24 35 46 57 68 79 8A 9B AC BD CE DF E0 F1",
                "key": "01 23 45 67 89 AB CD EF 01 12 23 34 45 56 67 78",
                "ciphertext": "52 4E 19 2F 47 15 C6 23 1F 51 F6 36 7E A4 3F 18"
            },
            {
                "plaintext": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "key": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "ciphertext": "6C D6 1B CB 19 0B 30 38 4E 8A 3F 16 86 90 AE 82"
            },
            {
                "plaintext": "02 13 24 35 46 57 68 79 8A 9B AC BD CE DF E0 F1",
                "key": "01 23 45 67 89 AB CD EF 01 12 23 34 45 56 67 78 89 9A AB BC CD DE EF F0",
                "ciphertext": "68 83 29 D0 19 E5 05 04 1E 52 E9 2A F9 52 91 D4"
            },
            {
                "plaintext": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "key": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "ciphertext": "8F 5F BD 05 10 D1 5F A8 93 FA 3F DA 6E 85 7E C2"
            },
            {
                "plaintext": "02 13 24 35 46 57 68 79 8A 9B AC BD CE DF E0 F1",
                "key": "01 23 45 67 89 AB CD EF 01 12 23 34 45 56 67 78 89 9A AB BC CD DE EF F0 10 32 54 76 98 BA DC FE",
                "ciphertext": "C8 24 18 16 F0 D7 E4 89 20 AD 16 A1 67 4E 5D 48"
            }
        ];

        testVectors.forEach(testVector => {
            let uint8ArrayFromHexStrng = (str: string) => {
                let arr = [];
                str.split(" ").forEach(val => {
                    arr.push(parseInt(val, 16));
                });
                return new Uint8Array(arr);
            };

            let enc = new RC6EncryptionAlgorithm();
            let text = uint8ArrayFromHexStrng(testVector["plaintext"]);
            let key = uint8ArrayFromHexStrng(testVector["key"]);
            let cipher = uint8ArrayFromHexStrng(testVector["ciphertext"]);

            let encrypted = enc.encryptBlock(text, key);

            assert.equal(encrypted.length, cipher.length, "Ciphertext length mismatch.");
            encrypted.every((val, i) => {
                assert.equal(val, cipher[i], "Ciphertext mismatch.");
            });

            let decrypted = enc.decryptBlock(encrypted, key);

            assert.equal(decrypted.length, text.length, "Decrypted length doesn't match plaintext length.");
            decrypted.every((val, i) => {
                assert.equal(val, text[i], "Decrypted doesn't match plaintext.");
            });

        });

        assert(true);
    });

});