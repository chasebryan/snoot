"""Recall seed: RSA-backed JWT signing."""
import jwt
token = jwt.encode({"sub": "42"}, "synthetic-key", algorithm="RS256")
