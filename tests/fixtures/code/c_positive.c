/* Positive fixture: SNOOT001, SNOOT002. */
#include <openssl/rsa.h>
#include <openssl/ec.h>

void generate(void) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL); /* SNOOT001 */
    ECDSA_sign(0, dgst, 32, sig, &siglen, eckey); /* SNOOT002 */
}
