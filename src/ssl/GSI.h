#ifndef PyOpenSSL_SSL_GSI_H
#define PyOpenSSL_SSL_GSI_H_

#include <openssl/ssl.h>

//static int null_callback(int ok, X509_STORE_CTX *e);
//static int internal_verify(X509_STORE_CTX *ctx);
int GSI_name_issuer_check( char *iname, char *sname );
int ssl_callback_GSI_verify( X509_STORE_CTX * ctx, void *dummy );

#endif
