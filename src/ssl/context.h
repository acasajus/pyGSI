
/*
 * context.h
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * Export SSL Context object data structures and functions.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 *
 * @(#) $Id: context.h,v 1.5 2008/07/08 10:54:55 acasajus Exp $
 */
#ifndef PyGSI_SSL_CONTEXT_H_
#define PyGSI_SSL_CONTEXT_H_

#include <Python.h>
#include <openssl/ssl.h>

extern int init_ssl_context( PyObject * );

extern PyTypeObject ssl_Context_Type;

#define ssl_Context_Check(v) ((v)->ob_type == &ssl_Context_Type)

typedef struct
{
    PyObject_HEAD SSL_CTX *ctx;
    char clientMethod;
    PyObject *passphrase_callback,
        *passphrase_userdata, *verify_callback, *info_callback, *app_data;
    PyThreadState *tstate;
} ssl_ContextObj;

#define ssl_SSLv3_METHOD         (4)
#define ssl_SSLv3_CLIENT_METHOD  (5)
#define ssl_SSLv3_SERVER_METHOD  (6)
#define ssl_SSLv23_METHOD        (7)
#define ssl_SSLv23_CLIENT_METHOD (8)
#define ssl_SSLv23_SERVER_METHOD (9)
#define ssl_TLSv1_METHOD         (10)
#define ssl_TLSv1_CLIENT_METHOD  (11)
#define ssl_TLSv1_SERVER_METHOD  (12)
#define ssl_TLSv1_1_METHOD         (13)
#define ssl_TLSv1_1_CLIENT_METHOD  (14)
#define ssl_TLSv1_1_SERVER_METHOD  (15)
#define ssl_TLSv1_2_METHOD         (16)
#define ssl_TLSv1_2_CLIENT_METHOD  (17)
#define ssl_TLSv1_2_SERVER_METHOD  (18)


#endif
