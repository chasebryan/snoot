#include <openssl/ssl.h>

SSL_CTX *make_ctx(void) {
  return SSL_CTX_new(TLS_server_method());
}
