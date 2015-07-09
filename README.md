# ig-js-utils

## Encryption and signing

The core encryption and signing capabilities are provided by the CryptoCoinJS library. As CryptoCoinJS has been designed 
 to run on NodeJS, the required components have been compiled into __/lib/ecdsa_bundle.js__, using [Browserify](http://browserify.org/).
 
 
### Browserify compilation 
 
 *The __/lib/ecdsa_bundle.js__ file has been compiled using Browserify. There is no need to do this, as it has been included
  here, so this is purely informational*.
  
 The script used to compile the required CryptoCoinJS libraries is as follows:
  
  node_main.js:
  
  ```
  var crypto = require('crypto');
  var ecdsa = require('ecdsa');
  var secureRandom = require('secure-random');
  var CoinKey = require('coinkey');
  var Buffer = require('buffer');
  var binString = require('binstring');
  var AES = require('aes');
  var pbkdf2 = require('pbkdf2-sha256');
  var BigInteger = require('bigi');
  ```
  
  from terminal run:
  
  ```
  browserify -r ecdsa -r crypto -r secure-random -r aes -r coinkey -r buffer -r binstring -r pbkdf2-sha256 node_main.js > ecdsa_bundle.js
  ```
  
 This outputs a js file called 'ecdsa_bundle.js'
   
### Utility functions
 
 The main utility functions are contained in __crypto/cryptoUtil.js__. 