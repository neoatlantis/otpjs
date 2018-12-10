(function(){
/****************************************************************************/


const base32 = require('base32.js');
const sha1 = require('js-sha1');


const decodeUTF8 = function(s) {
    if (typeof s !== 'string') throw new TypeError('expected string');
    var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
    for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
    return b;
};


function OTP(secret, encoding="base32"){
    /**
     * Construct an instance of the OTP generator with a shared secret.
     * @param {string} secret The shared secret used to generate and validate the OTP.
     */

    var self = this;
    var secret;

    if (encoding === 'base32') {
        secret = new Uint8Array(new base32.Decoder().write(secret).finalize());
    } else {
        secret = decodeUTF8(secret);
    }


    /**
     * Calculate a time-based one-time password (TOTP), as defined in RFC-6238
     * A TOTP is an HOTP that uses a time interval as the counter.
     * @returns {string} A six-digit OTP value
     */
    self.getTOTP = function(digits = 6) {
        // Get the current epoch, rounded to intervals of 30 seconds
        const now = Math.floor((new Date()).getTime() / 1000)
        const epoch = Math.floor(now / 30)

        // Calcule an HOTP using the epoch as the counter
        return self.getHOTP(String(epoch), digits)
    }

    function HMAC(data) {
        var oKeyPad, iKeyPad, iPadRes, bytes, i, len;
        var key = new Uint8Array(secret);

        function merge(a, b){
            var ret = new Uint8Array(a.length + b.length);
            ret.set(a);
            ret.set(b, a.length);
            return ret;
        }

        if (key.length > 64) {
            // keys longer than blocksize are shortened
            key = new Uint8Array(sha1.array(key));
        }

        bytes = new Uint8Array(64);
        len = key.length;
        for (i = 0; i < 64; ++i) {
            bytes[i] = len > i ? key[i] : 0x00;
        }

        oKeyPad = new Uint8Array(64);
        iKeyPad = new Uint8Array(64);

        for (i = 0; i < 64; ++i) {
            oKeyPad[i] = bytes[i] ^ 0x5C;
            iKeyPad[i] = bytes[i] ^ 0x36;
        }

        iPadRes = new Uint8Array(sha1.array(merge(iKeyPad, data)));
        return new Uint8Array(sha1.array(merge(oKeyPad, iPadRes)));
    }

    /**
     * Calculate a 6-digit HMAC-based one-time password (HOTP), as defined in RFC-4226
     * @param {string} counter A distinct counter value used to generate an OTP with the secret.
     * @returns {string} A six-digit OTP value
     */
    self.getHOTP = function(counter, digits = 6) {
        // Calculate an HMAC encoded value from the secret and counter values
        const encodedCounter = encodeCounter(counter)
        const hmacDigest = HMAC(encodedCounter)

        // Extract a dynamically truncated binary code from the HMAC result
        const binaryCode = getBinaryCode(hmacDigest)

        // Convert the binary code to a number between 0 and 1,000,000
        const hotp = convertToHotp(binaryCode, digits)
        return hotp
    }

    /**
     * Extract the dynamic binary code from an HMAC-SHA-1 result.
     * @param {Uint8Array} digest The digest should be a 20-byte Uint8Array
     * @returns {number} A 31-bit binary code integer
     */
    function getBinaryCode (digest) {
      const offset  = digest[digest.length - 1] & 0xf
      const binaryCode = (
        ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff))

      return binaryCode
    }

    /**
     * Convert a binary code to a 6 digit OTP value
     * @param {number} number A 31-bit binary code
     * @returns {number} An n-digit string of numbers
     */
    function convertToHotp (number, digits = 6) {
      // Convert binary code to an up-to 6 digit number
      const otp = number % Math.pow(10, digits)

      // If the resulting number has fewer than n digits, pad the front with zeros
      return String(otp).padStart(digits, '0')
    }

    /** Encode the counter values as an 8 byte array buffer. */
    function encodeCounter (counter) {
      // Convert the counter value to an 8 byte bufer
      // Adapted from https://github.com/speakeasyjs/speakeasy
      const buf = new Uint8Array(8);
      let tmp = counter;
      for (let i = 0; i < 8; i++) {
          // Mask 0xff over number to get last 8
          buf[7 - i] = tmp & 0xff;

          // Shift 8 and get ready to loop over the next batch of 8
          tmp = tmp >> 8;
      }

      return buf
    }



    return self;
}

module.exports = OTP;





/****************************************************************************/
})();
