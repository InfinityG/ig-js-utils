window.cryptoUtil = (function () {
    function CryptoUtil() {}

    var cryptoUtil = {

        AES: {
            generateAESKey: function (password, salt) {
                var pbkdf2 = require('pbkdf2-sha256');
                var BigInteger = require('bigi');

                // generate byte array with length 64
                var buffer = pbkdf2(password, salt, 1, 64);

                // split the byte array into 8 chunks of 8 bytes - create a bigint from each 8 byte chunk
                var quadArr = [];
                for(var x=0; x< buffer.length; x+=8){
                    var chunk = BigInteger.fromBuffer(buffer.slice(x, x+8));
                    quadArr.push(chunk);
                }
                return quadArr;
            },

            encryptTextToBase64: function(cryptoKey, data){
                var buf = require('buffer');
                var buffer = new buf.Buffer(data);
                return cryptoUtil.AES.encryptBufferToBase64(cryptoKey, buffer);
            },

            encryptBufferToBase64: function (cryptoKey, buffer) {
                var encryptedBuffer = cryptoUtil.AES.encryptBuffer(cryptoKey, buffer);
                return encryptedBuffer.toString('base64');
            },

            // output is an encrypted buffer
            encryptBuffer: function(cryptoKey, buffer){
                //order: buffer > unencrypted uint array > encrypted uint array > buffer
                try {
                    var aes = cryptoUtil.AES.getAESInstance(cryptoKey);
                    //convert buffer to int array
                    var decIntArr = cryptoUtil.AES.compressBufferToIntArray(buffer);
                    //result is an int array
                    var encIntArr = [];

                    //iterate through buffer and encrypt every block of 4
                    var pos = 0;
                    while (pos < decIntArr.length) {
                        var block = decIntArr.slice(pos, pos + 4);
                        cryptoUtil.AES.pad(block);  //pad the last block if necessary
                        var encBlock = aes.encrypt(block);  //output is also an int array length 4

                        for(var i=0; i<encBlock.length; i++){
                            encIntArr.push(encBlock[i]);
                        }

                        pos += 4;
                    }

                    //result is a uint array - we need to get this back to a buffer
                    return cryptoUtil.AES.decompressIntArrayToBuffer(encIntArr);
                } catch (e) {
                    console.debug('Encryption error: ' + e.message);
                    throw e;
                }
            },

            compressBufferToIntArray: function(buffer){
                //eg: compress 32 byte buffer into uint array length 8

                var BigInteger = require('bigi');
                var result = [];
                var pos = 0;

                while (pos < buffer.length) {
                    var block = buffer.slice(pos, pos + 4);
                    cryptoUtil.AES.pad(block);

                    //convert each block of 4 into a bigint
                    var int = BigInteger.fromBuffer(block);

                    result.push(int);
                    pos += 4;
                }

                return result;
            },

            decompressIntArrayToBuffer: function(intArr){
                //eg: decompress uint array length 8 to buffer length 32
                var BigInteger = require('bigi');
                var buf = require('buffer');

                var result = [];

                for(var x=0; x<intArr.length; x++){
                    var bufChunk = (new BigInteger(intArr[x].toString())).toBuffer(4); //cast uint to buffer length 4

                    for(var i=0; i<bufChunk.length ; i++){
                        result.push(bufChunk[i]);
                    }
                }

                return new buf.Buffer(result);
            },

            decryptBase64ToText: function (cryptoKey, base64CipherText) {
                var result = cryptoUtil.AES.decryptBase64ToBuffer(cryptoKey, base64CipherText);
                return result.toString('utf8');
            },

            decryptBase64ToBuffer: function (cryptoKey, base64CipherText) {
                var buf = require('buffer');
                var buffer = new buf.Buffer(base64CipherText, 'base64');
                return cryptoUtil.AES.decryptBuffer(cryptoKey, buffer);
            },

            // output is an decrypted buffer
            decryptBuffer: function(cryptoKey, buffer){
                //order: buffer > encrypted uint array > decrypted uint array > buffer

                try {
                    var aes = cryptoUtil.AES.getAESInstance(cryptoKey);
                    var encIntArr = cryptoUtil.AES.compressBufferToIntArray(buffer);
                    var decIntArr = [];

                    //iterate through buffer and decrypt every block of 4
                    var pos = 0;
                    while (pos < encIntArr.length) {
                        var block = encIntArr.slice(pos, pos + 4);
                        var decBlock = aes.decrypt(block);  //result is also a unit array length 4

                        for(var i=0; i<decBlock.length; i++){
                            decIntArr.push(decBlock[i]);
                        }

                        pos += 4;
                    }

                    //decIntArr is a uint array - we need to get this back to a buffer
                    return cryptoUtil.AES.decompressIntArrayToBuffer(decIntArr);

                } catch (e) {
                    console.debug('Decryption error: ' + e.message);
                    throw e;
                }
            },

            validateAESKey: function (cryptoKey, unencryptedTextToCompare, base64CipherTextOriginal) {
                var encrypted = cryptoUtil.AES.encryptTextToBase64(cryptoKey, unencryptedTextToCompare);
                return (encrypted == base64CipherTextOriginal);
            },

            getAESInstance: function (key) {
                var AES = require('aes');
                return new AES(key);
            },

            pad: function (block) {
                while (block.length < 4) {
                    block.push(0);
                }
            },

            base64Encode: function (text) {
                var buf = require('buffer');
                var buffer = new buf.Buffer(text);
                return buffer.toString('base64');
            },

            base64Decode: function (text) {
                var buf = require('buffer');
                var buffer = new buf.Buffer(text, 'base64');
                return buffer.toString();
            }

        },

        ECDSA: {
            createSigningKeyPair: function () {
                var sr = require('secure-random');
                var CoinKey = require('coinkey');
                var privateKey = sr.randomBuffer(32);   // a random buffer
                var ck = new CoinKey(privateKey, true); // true => compressed public key / addresses

                return {pk: ck.publicKey, sk: ck.privateKey};
            },

            createMessageDigest: function (messageText) {
                var crypto = require('crypto');
                var buf = require('buffer');

                var msg = new buf.Buffer(messageText, 'utf8');
                return crypto.createHash('sha256').update(msg).digest();
            },

            signMessage: function (messageDigestBuffer, privateKeyBuffer) {
                var ecdsa = require('ecdsa');
                var buf = require('buffer');

                var signature = ecdsa.sign(messageDigestBuffer, privateKeyBuffer);
                var serialisedSig = ecdsa.serializeSig(signature);

                return buf.Buffer(serialisedSig);
            },

            validateSignature: function(messageDigestBuffer, signatureBuffer, base64PublicKey){
                var ecdsa = require('ecdsa');
                var buf = require('buffer');
                var keyBuffer = new buf.Buffer(base64PublicKey, 'base64');
                var parsedSigBuffer = ecdsa.parseSig(signatureBuffer);
                return ecdsa.verify(messageDigestBuffer, parsedSigBuffer, keyBuffer)
            }
        },

        textToIntArray: function (s) {
            var ua = [];
            for (var i = 0; i < s.length; i++) {
                ua[i] = s.charCodeAt(i);
            }
            return ua;
        },

        intArrayToText: function (ua) {
            var s = '';
            for (var i = 0; i < ua.length; i++) {
                s += String.fromCharCode(ua[i]);
            }
            return s;
        }

    };

    return cryptoUtil;
}());
