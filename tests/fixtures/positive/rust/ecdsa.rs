use p256::ecdsa::SigningKey;

fn new_signer(mut rng: impl rand::CryptoRng + rand::RngCore) -> SigningKey {
    SigningKey::random(&mut rng)
}
