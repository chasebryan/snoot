# snoot — announcement draft (NOT POSTED)

snoot finds the cryptography quantum computers will break — RSA, ECDSA,
Diffie-Hellman hiding in your code, keys, and configs — and maps each one
to its NIST post-quantum replacement.

A pre-alpha tool for planning post-quantum migration. Its static inventory
helps identify call sites for review; it does not certify a repository safe.

Build from the repository with `cargo install --path . --locked`.
Publish/install instructions will be updated after the release gates pass.

https://github.com/chasebryan/snoot

Honest limits: heuristic detection, no data-flow analysis, recall
unmeasured. It finds what it can see; it won't certify you clean. Full
accuracy notes: docs/accuracy.md.
