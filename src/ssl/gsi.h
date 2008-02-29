#ifndef PyOpenSSL_SSL_GSI_H
#define PyOpenSSL_SSL_GSI_H_

#include <openssl/ssl.h>

#define GRST_PROXYCERTINFO_OID	"1.3.6.1.4.1.3536.1.222"

#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

#define GRST_CERT_BAD_FORMAT 1
#define GRST_CERT_BAD_CHAIN  2
#define GRST_CERT_BAD_SIG    4
#define GRST_CERT_BAD_TIME   8
#define GRST_CERT_BAD_OCSP  16

#define GRST_CERT_TYPE_CA    1
#define GRST_CERT_TYPE_EEC   2
#define GRST_CERT_TYPE_PROXY 3

// Everything ok (= OpenSSL X509_V_OK)
#define GRST_RET_OK		0

// Failed for unspecified reason
#define GRST_RET_FAILED		1000

typedef struct { int    type;		/* CA, user, proxy, VOMS, ... */
                 int    errors;		/* unchecked, bad sig, bad time */
                 char   *issuer;	/* Cert CA DN, EEC of PC, or VOMS DN */
                 char   *dn;		/* Cert DN, or VOMS AC holder DN */
                 char   *value;		/* VOMS FQAN or NULL */
                 time_t notbefore;
                 time_t notafter;
                 int    delegation;	/* relative to END of any chain */
                 int    serial;
                 char   *ocsp;		/* accessLocation field */
                 void   *raw;		/* X509 or VOMS Extension object */
                 void   *next; } GRSTx509Cert;

/* a chain of certs, starting from the first CA */
typedef struct { GRSTx509Cert *firstcert; } GRSTx509Chain;

int gsiVerifyCertWrapper(X509_STORE_CTX *ctx, void *p);
int gsiX509CheckIssuedWrapper(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);

int gsiVerifyCallback( int ok, X509_STORE_CTX *ctx );
unsigned long gsiVerifyProxyChain( STACK_OF(X509) *certstack );
int GRSTx509KnownCriticalExts(X509 *cert);
int GRSTx509IsCA(X509 *cert);

int GRSTx509ChainLoadCheck(GRSTx509Chain **chain,
                           STACK_OF(X509) *certstack, X509 *lastcert,
                           char *capath );

unsigned long grid_verifyProxy( STACK_OF(X509) *certstack );
int GRSTx509ChainFree(GRSTx509Chain *chain);

#endif
