use rsa::{RsaPrivateKey, RsaPublicKey};

fn issue_key(mut rng: impl rand::RngCore) -> RsaPrivateKey {
    Rsa::generate(&mut rng, 2048).expect("rsa keygen")
}

fn issue_key_alt(mut rng: impl rand::CryptoRng + rand::RngCore) -> RsaPrivateKey {
    RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen")
}
