fn weak_dh(mut rng: impl rand::RngCore) {
    let _params = Dh::generate(&mut rng);
}
