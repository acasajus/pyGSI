
/*
 * connection.h
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * Export SSL Connection data structures and functions.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 *
 * @(#) $Id: session.h,v 1.3 2008/07/08 10:54:55 acasajus Exp $
 */
#ifndef PyGSI_SSL_SESSION_H_
#define PyGSI_SSL_SESSION_H_

#include <Python.h>
#include <openssl/ssl.h>


extern int init_ssl_session( PyObject * );

extern PyTypeObject ssl_Session_Type;

#define ssl_Session_Check(v) ((v)->ob_type == &ssl_Session_Type)

typedef struct
{
    PyObject_HEAD SSL_SESSION *session;
    PyObject *socket;
    PyThreadState *tstate;
    PyObject *app_data;
} ssl_SessionObj;


#endif
