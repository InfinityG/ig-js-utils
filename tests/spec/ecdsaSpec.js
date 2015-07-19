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
});