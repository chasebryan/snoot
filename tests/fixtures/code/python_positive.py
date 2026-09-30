"""Positive fixture: SNOOT001, SNOOT002, SNOOT013, SNOOT014."""
import hashlib

import Crypto.PublicKey.RSA
from ecdsa import SigningKey

rsa_key = Crypto.PublicKey.RSA.generate(2048)  # SNOOT001
ec_key = SigningKey.generate()  # SNOOT002
digest = hashlib.md5(b"data").hexdigest()  # SNOOT013
token = jwt.encode({"sub": "1"}, rsa_key, algorithm="RS256")  # SNOOT014
