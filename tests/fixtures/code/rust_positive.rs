// Positive fixture: SNOOT001, SNOOT002, SNOOT013.

fn rsa_keygen() {
    let _key = Rsa::generate(2048).unwrap();
}

fn ecdsa_sign() {
    let _sk = SigningKey::random(&mut rand::thread_rng());
}

fn legacy_hashes(data: &[u8]) {
    let _h = Md5::new();
    let _d = md5::compute(data);
}
