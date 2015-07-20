# ig-js-utils

## Encryption and signing

The core encryption and signing capabilities are provided by the CryptoCoinJS library. As CryptoCoinJS has been designed 
 to run on NodeJS, the required components have been compiled into __/lib/cryptoBundle.js__, using [Browserify](http://browserify.org/).
 
 
### Browserify compilation 
 
 *The __/lib/cryptoBundle.js__ file has been compiled using Browserify. As this is included in the __/lib__ directory, 
 you shouldn't need to do this, so this is purely informational*.
  
  - Run ```npm install``` in the root to install dependencies
  - Then run:
  
   ```
   browserify -r ecdsa -r crypto -r bigi -r secure-random -r aes -r coinkey -r buffer -r binstring -r pbkdf2-sha256 input.js > src/lib/cryptoBundle.js
   ```
  - This will use ```input.js``` as the input file, and will generate an output file called ```cryptoBundle.js```
   
### Utility functions
 
 The main utility functions are contained in __crypto/cryptoUtil.js__. 