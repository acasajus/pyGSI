#ifndef PyGSI_SSL_GSI_H
#define PyGSI_SSL_GSI_H

#include <openssl/ssl.h>

#define GSI_PROXYCERTINFO_OID "1.3.6.1.4.1.3536.1.222"

#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

// Everything ok (= OpenSSL X509_V_OK)
#define GSI_RET_OK      0
// Failed for unspecified reason
#define GSI_RET_FAILED     1000

int gsiVerifyCertWrapper( X509_STORE_CTX * ctx, void *p );
int gsiCheckIssuedWrapper( X509_STORE_CTX * ctx, X509 * x, X509 * issuer );

int gsiVerifyCallback( int ok, X509_STORE_CTX * ctx );
unsigned long gsiVerifyProxyChain( STACK_OF( X509 ) * certstack );
int gsiCheckKnownCriticalExt( X509 * cert );
int gsiCheckIsCA( X509 * cert );
time_t gsiAsn1TimeToTimeT( unsigned char *asn1time, size_t len );

#endif
