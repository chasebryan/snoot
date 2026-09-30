// Positive fixture: SNOOT001, SNOOT014.
const crypto = require("crypto");

const key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }); // SNOOT001
const token = jwt.sign(payload, secret, { algorithm: "RS256" }); // SNOOT014
