window.cryptoUtil = (function () {
    function CryptoUtil() {

    }

    var cryptoUtil = {

        AES: {
            generateAESKey: function (password, salt) {
                var pbkdf2 = require('pbkdf2-sha256');
                var BigInteger = require('bigi');

                // generate byte array with length 64
                var buffer = pbkdf2(password, salt, 1, 64);
                
                // split the byte array into 4 chunks of 16 bytes - create a bigint from each 16 byte chunk
                var quadArr = [];
                for(var x=0; x< buffer.length; x+=16){
                    quadArr.push(BigInteger.fromBuffer(buffer.slice(x, x+16)));
                }
                return quadArr;
            },

            encryptStringToBase64: function (cryptoKey, plainText) {
                var buf = require('buffer');
                var buffer = new buf.Buffer(plainText);

                var encryptedString = cryptoUtil.AES.encryptBufferToString(cryptoKey, buffer);
                return cryptoUtil.AES.base64Encode(encryptedString);
            },

            encryptBufferToBase64: function (cryptoKey, buffer) {
                var encryptedString = cryptoUtil.AES.encryptBufferToString(cryptoKey, buffer);
                return cryptoUtil.AES.base64Encode(encryptedString);
            },

            encryptBufferToString: function (cryptoKey, buffer) {
                try {
                    var aes = cryptoUtil.AES.getAESInstance(cryptoKey);
                    var cipherText = '';

                    //iterate through buffer and encrypt every block of 4
                    var pos = 0;
                    while (pos < buffer.length) {
                        var block = buffer.slice(pos, pos + 4);
                        cryptoUtil.AES.pad(block); //pad the last block if necessary
                        var encBlock = aes.encrypt(block);
                        for (var x = 0; x < encBlock.length; x++) {
                            cipherText += encBlock[x] + ',';
                        }
                        pos += 4;
                    }
                } catch (e) {
                    console.debug('Encryption error: ' + e.message);
                    throw e;
                }

                return cipherText.substring(0, cipherText.length - 1); //remove the last comma
            },

            decryptBase64ToString: function (cryptoKey, cipherText) {
                var decryptedBuffer = cryptoUtil.AES.decryptBase64ToBuffer(cryptoKey, cipherText);
                return decryptedBuffer.toString('utf-8')
            },

            decryptBase64ToBuffer: function (cryptoKey, cipherText) {
                var decodedText = cryptoUtil.AES.base64Decode(cipherText);
                return cryptoUtil.AES.decryptStringToBuffer(cryptoKey, decodedText);
            },

            decryptStringToBuffer: function (cryptoKey, decodedText) {
                try {
                    var aes = cryptoUtil.AES.getAESInstance(cryptoKey);
                    var arr = decodedText.split(',');

                    var result = [];

                    //iterate through array and decrypt every block of 4
                    var pos = 0;
                    while (pos < arr.length) {
                        var block = arr.slice(pos, pos + 4);
                        var decArr = aes.decrypt(block);

                        for (var x = 0; x < decArr.length; x++) {
                            result.push(decArr[x]);
                        }

                        pos += 4;
                    }
                } catch (e) {
                    console.debug('Decryption error: ' + e.message);
                    throw e;
                }

                var buf = require('buffer');
                return new buf.Buffer(result);
            },

            validateAESKey: function (cryptoKey, cipherTextOriginal) {
                var decrypted = cryptoUtil.AES.decryptBase64ToBuffer(cryptoKey, cipherTextOriginal);
                var encrypted = cryptoUtil.AES.encryptBufferToBase64(cryptoKey, decrypted);

                var result = (encrypted == cipherTextOriginal);

                //event for modals
                if (!result) {
                    throw new Error('AES key validation error');
                }

                return result;
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

            createMessageDigest: function (message) {
                var crypto = require('crypto');
                var buf = require('buffer');

                var msg = new buf.Buffer(message, 'utf8');
                return crypto.createHash('sha256').update(msg).digest();
            },

            signMessage: function (messageDigest, privateKeyBuffer) {
                var ecdsa = require('ecdsa');
                var buf = require('buffer');

                var signature = ecdsa.sign(messageDigest, privateKeyBuffer);
                var serialisedSig = ecdsa.serializeSig(signature);

                return buf.Buffer(serialisedSig);
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
