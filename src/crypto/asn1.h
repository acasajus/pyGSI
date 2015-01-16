#ifndef PyGSI_crypto_ASN1_H_
#define PyGSI_crypto_ASN1_H_

#include <Python.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>

typedef struct crypto_ASN1 {
  PyObject_HEAD
  int tag;
  int class;
  int compound;
  void* data;
  struct crypto_ASN1** children;
  long num_children;
} crypto_ASN1;

extern int init_crypto_ASN1( PyObject* );
static PyTypeObject crypto_ASN1_Type;
extern PyObject* crypto_ASN1_loads(PyObject *, PyObject*);
crypto_ASN1* loads_asn1(char* buf, long len, long *len_done );
int crypto_ASN1_inner_dump(crypto_ASN1*, BIO*); 

#define crypto_ASN1_Check(v) ((v)->ob_type == \ &crypto_ASN1_Type)

#endif
