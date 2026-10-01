# snoot — announcement draft (NOT POSTED)

snoot finds the cryptography quantum computers will break — RSA, ECDSA,
Diffie-Hellman hiding in your code, keys, and configs — and maps each one
to its NIST post-quantum replacement.

An experimental inventory tool for planning post-quantum migration. Its static inventory
helps identify call sites for review; it does not certify a repository safe.

The v0.1.0 release includes a GitHub Action and five native CLI archives.
See the README for verified installation, workflow permissions, and the action
contract. Publish this announcement only after the public release and
Marketplace listing are confirmed.

https://github.com/chasebryan/snoot

Honest limits: heuristic detection, no data-flow analysis, recall
unmeasured. It finds what it can see; it won't certify you clean. Full
accuracy notes: docs/accuracy.md.
