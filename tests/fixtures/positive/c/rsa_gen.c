#include <openssl/rsa.h>

void make_key(RSA *rsa, BIGNUM *e) {
  RSA_generate_key_ex(rsa, 2048, e, NULL);
}
