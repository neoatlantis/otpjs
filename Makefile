all: src/otp.js
	mkdir -p dist
	browserify src/otp.js -o dist/otp.js --standalone otpjs
