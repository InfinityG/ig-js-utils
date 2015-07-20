describe("ECDSA", function () {

    it("should generate ECDSA public/private key pair", function () {
        var result = cryptoUtil.ECDSA.createSigningKeyPair();

        expect(result).not.toBe('');
        expect(result.sk).not.toBe('');
        expect(result.pk).not.toBe('');
    });

    it("should successfully create message digest", function () {
        var message = '{"testField":"testData"}';
        var digest = cryptoUtil.ECDSA.createMessageDigest(message);

        expect(digest).not.toBe('');
    });

    it("should successfully sign a message with a private key", function () {
        var message = '{"testField":"testData"}';
        var keys = cryptoUtil.ECDSA.createSigningKeyPair();
        var digest = cryptoUtil.ECDSA.createMessageDigest(message);
        var signature = cryptoUtil.ECDSA.signMessage(digest, keys.sk);

        expect(signature).not.toBe('');
    });

    it("should pass validation of a signed message with a valid public key", function () {
        var message = '{"testField":"testData"}';
        var keys = cryptoUtil.ECDSA.createSigningKeyPair();
        var digest = cryptoUtil.ECDSA.createMessageDigest(message);
        var signature = cryptoUtil.ECDSA.signMessage(digest, keys.sk);

        var result = cryptoUtil.ECDSA.validateSignature(digest, signature, keys.pk.toString('base64'));

        expect(result).not.toBe(false);
    });

    it("should fail validation of a signed message with an incorrect public key", function () {
        var message = '{"testField":"testData"}';
        var keys = cryptoUtil.ECDSA.createSigningKeyPair();
        var digest = cryptoUtil.ECDSA.createMessageDigest(message);
        var signature = cryptoUtil.ECDSA.signMessage(digest, keys.sk);

        var newKeys = cryptoUtil.ECDSA.createSigningKeyPair();  //create a different set of keys
        var result = cryptoUtil.ECDSA.validateSignature(digest, signature, newKeys.pk.toString('base64'));

        expect(result).not.toBe(true);
    });
});