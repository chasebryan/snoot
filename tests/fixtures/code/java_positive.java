// Positive fixture: SNOOT001, SNOOT002.
class Crypto {
    void generate() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // SNOOT001
        Signature sig = Signature.getInstance("SHA256withECDSA"); // SNOOT002
    }
}
