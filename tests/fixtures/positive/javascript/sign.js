const crypto = require('crypto');
const signer = crypto.createSign('RSA-SHA256');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
