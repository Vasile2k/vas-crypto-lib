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

        assert.equal(decrypted.length, plainText.length, "Decrypted lenght doesn't match plaintext length.");

        decrypted.every((val, i) => {
            assert.equal(val, plainText[i], "Decrypted doesn't match plaintext.");
        });
    });

    it("should match test vectors", () => {

        // TODO: add test vectors

        assert(true);
    });

});