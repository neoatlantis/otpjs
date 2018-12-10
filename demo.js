const OTP = require("./dist/otp.js");

const secret1 = "12345678901234567890";
const secret2 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const otp1 = new OTP(secret1, "utf-8"),
      otp2 = new OTP(secret2);

console.log(otp1.getHOTP(0), otp2.getHOTP(0), "<- must be 2x 755224");
console.log(otp1.getHOTP(9), otp2.getHOTP(9), "<- must be 2x 520489");
console.log(otp1.getTOTP());
