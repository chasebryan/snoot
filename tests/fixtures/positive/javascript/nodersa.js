const NodeRSA = require('node-rsa');
const key = new NodeRSA({ b: 2048 });
key.generateKeyPair(2048);
crypto.privateEncrypt(key, Buffer.from('hi'));
