#ifndef PyGSI_crypto_ASN1_H_
#define PyGSI_crypto_ASN1_H_

#include <Python.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>

typedef struct crypto_ASN1Obj {
  PyObject_HEAD
  int tag;
  int class;
  int compound;
  void* data;
  struct crypto_ASN1Obj** children;
  long num_children;
} crypto_ASN1Obj;

extern int init_crypto_ASN1Obj( PyObject* );
static PyTypeObject crypto_ASN1Obj_Type;
extern PyObject* crypto_ASN1_loads(PyObject *, PyObject*);
extern PyObject* crypto_ASN1_dumps(PyObject *, PyObject*);
crypto_ASN1Obj* loads_asn1(char* buf, long len, long *len_done );

#define crypto_ASN1Obj_Check(v) ((v)->ob_type == \ &crypto_ASN1Obj_Type)

#endif