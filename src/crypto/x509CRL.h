#ifndef PyGSI_crypto_X509CRL_H_
#define PyGSI_crypto_X509CRL_H_

#include <Python.h>
#include <openssl/x509.h>

extern int init_crypto_x509CRL( PyObject * );

extern PyTypeObject crypto_X509CRL_Type;

#define crypto_x509CRL_Check(v) ((v)->ob_type == &crypto_x509CRL_Type)

typedef struct
{
    PyObject_HEAD X509_CRL *crl;
    int dealloc;
} crypto_X509CRLObj;


#endif

