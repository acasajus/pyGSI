#include <Python.h>
#define SSL_MODULE
#include "ssl.h"

static char ssl_doc[] = "\n\
Main file of the SSL sub module.\n\
See the file RATIONALE for a short explanation of hy this module was written.\n\
";

void **crypto_API;

/* Exceptions defined by the SSL submodule */
PyObject *ssl_Error,            /* Base class */
 *ssl_ZeroReturnError,          /* Used with SSL_get_error */
 *ssl_WantReadError,            /* ...  */
 *ssl_WantWriteError,           /* ...  */
 *ssl_WantX509LookupError,      /* ...  */
 *ssl_SysCallError;             /* Uses (errno,errstr) */

static char ssl_Context_doc[] = "\n\
The factory function inserted in the module dictionary to create Context\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             method - The SSL method to use\n\
Returns:   The Context object\n\
";

static PyObject *
ssl_Context( PyObject * spam, PyObject * args )
{
    int method;

    if ( !PyArg_ParseTuple( args, "i:Context", &method ) )
        return NULL;

    return ( PyObject * ) ssl_Context_New( method );
}

static char ssl_Connection_doc[] = "\n\
The factory function inserted in the module dictionary to create Connection\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             ctx  - An SSL Context to use for this connection\n\
             sock - The socket to use for transport layer\n\
Returns:   The Connection object\n\
";

static PyObject *
ssl_Connection( PyObject * spam, PyObject * args )
{
    ssl_ContextObj *ctx;
    PyObject *sock;

    if ( !PyArg_ParseTuple
         ( args, "O!O:Connection", &ssl_Context_Type, &ctx, &sock ) )
        return NULL;

    return ( PyObject * ) ssl_Connection_New( ctx, sock );
}

static char ssl_Session_doc[] = "\n\
The factory function inserted in the module dictionary to create Session\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The Session object\n\
";

static PyObject *
ssl_Session( PyObject * spam, PyObject * args )
{

    if ( !PyArg_ParseTuple( args, ":Session" ) )
        return NULL;

    return ( PyObject * ) ssl_Session_New(  );
}

static char ssl_set_thread_safe_doc[] = "\n\
The factory function inserted in the module dictionary to set mutexes for SSL.\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if all went ok.\n\
";

static PyObject *
ssl_set_thread_safe( PyObject * spam, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":set_thread_safe" ) )
        return NULL;

    return Py_BuildValue( "i", initialize_locks(  ) );
}

#define ADD_METHOD(name)        \
	{ #name, (PyCFunction)ssl_##name, METH_VARARGS, ssl_##name##_doc }

/* Methods in the GSI.SSL module */
static PyMethodDef ssl_methods[] = {
    ADD_METHOD( Context ),
    ADD_METHOD( Connection ),
    ADD_METHOD( Session ),
    ADD_METHOD( set_thread_safe ),
    {NULL, NULL}
};

/*
 * Initialize SSL sub module
 *
 * Arguments: None
 * Returns:   None
 */
void
initSSL( void )
{
    static void *ssl_API[ssl_API_pointers];
    PyObject *ssl_api_object;
    PyObject *module, *dict;

    SSL_library_init(  );
    ERR_load_SSL_strings(  );

//  PyEval_InitThreads();
//  PyEval_ReleaseLock();

    import_crypto(  );

    if ( ( module = Py_InitModule3( "SSL", ssl_methods, ssl_doc ) ) == NULL )
        return;

    /* Initialize the C API pointer array */
    ssl_API[ssl_Context_New_NUM] = ( void * ) ssl_Context_New;
    ssl_API[ssl_Connection_New_NUM] = ( void * ) ssl_Connection_New;
    ssl_API[ssl_Session_New_NUM] = ( void * ) ssl_Session_New;
    ssl_api_object = PyCObject_FromVoidPtr( ( void * ) ssl_API, NULL );
    if ( ssl_api_object != NULL )
        PyModule_AddObject( module, "_C_API", ssl_api_object );

    /* Exceptions */

/*
 * ADD_EXCEPTION(dict,name,base) expands to a correct Exception declaration,
 * inserting GSI.SSL.name into dict, derviving the exception from base.
 */
#define ADD_EXCEPTION(_name, _base)                                    \
do {                                                                          \
    ssl_##_name = PyErr_NewException("GSI.SSL."#_name, _base, NULL);\
    if (ssl_##_name == NULL)                                            \
        goto error;                                                           \
    if (PyModule_AddObject(module, #_name, ssl_##_name) != 0)           \
        goto error;                                                           \
} while (0)

/*
    ssl_Error = PyErr_NewException( "GSI.SSL.Error", NULL, NULL );
    if ( ssl_Error == NULL )
        goto error;
    if ( PyModule_AddObject( module, "Error", ssl_Error ) != 0 )
        goto error;
*/

    ADD_EXCEPTION( Error, NULL );
    ADD_EXCEPTION( ZeroReturnError, ssl_Error );
    ADD_EXCEPTION( WantReadError, ssl_Error );
    ADD_EXCEPTION( WantWriteError, ssl_Error );
    ADD_EXCEPTION( WantX509LookupError, ssl_Error );
    ADD_EXCEPTION( SysCallError, ssl_Error );
#undef ADD_EXCEPTION

    /* Method constants */
    PyModule_AddIntConstant( module, "SSLv3_METHOD", ssl_SSLv3_METHOD );
    PyModule_AddIntConstant( module, "SSLv3_CLIENT_METHOD",
                             ssl_SSLv3_CLIENT_METHOD );
    PyModule_AddIntConstant( module, "SSLv3_SERVER_METHOD",
                             ssl_SSLv3_SERVER_METHOD );
    PyModule_AddIntConstant( module, "SSLv23_METHOD", ssl_SSLv23_METHOD );
    PyModule_AddIntConstant( module, "SSLv23_CLIENT_METHOD",
                             ssl_SSLv23_CLIENT_METHOD );
    PyModule_AddIntConstant( module, "SSLv23_SERVER_METHOD",
                             ssl_SSLv23_SERVER_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_METHOD", ssl_TLSv1_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_CLIENT_METHOD", ssl_TLSv1_CLIENT_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_SERVER_METHOD", ssl_TLSv1_SERVER_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_1_METHOD", ssl_TLSv1_1_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_1_CLIENT_METHOD", ssl_TLSv1_1_CLIENT_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_1_SERVER_METHOD", ssl_TLSv1_1_SERVER_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_2_METHOD", ssl_TLSv1_2_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_2_CLIENT_METHOD", ssl_TLSv1_2_CLIENT_METHOD );
    PyModule_AddIntConstant( module, "TLSv1_2_SERVER_METHOD", ssl_TLSv1_2_SERVER_METHOD );


    /* Verify constants */
    PyModule_AddIntConstant( module, "VERIFY_NONE", SSL_VERIFY_NONE );
    PyModule_AddIntConstant( module, "VERIFY_PEER", SSL_VERIFY_PEER );
    PyModule_AddIntConstant( module, "VERIFY_FAIL_IF_NO_PEER_CERT",
                             SSL_VERIFY_FAIL_IF_NO_PEER_CERT );
    PyModule_AddIntConstant( module, "VERIFY_CLIENT_ONCE",
                             SSL_VERIFY_CLIENT_ONCE );

    /* File type constants */
    PyModule_AddIntConstant( module, "FILETYPE_PEM", SSL_FILETYPE_PEM );
    PyModule_AddIntConstant( module, "FILETYPE_ASN1", SSL_FILETYPE_ASN1 );

    /* SSL option constants */
    PyModule_AddIntConstant( module, "OP_SINGLE_DH_USE",
                             SSL_OP_SINGLE_DH_USE );
    PyModule_AddIntConstant( module, "OP_EPHEMERAL_RSA",
                             SSL_OP_EPHEMERAL_RSA );
    PyModule_AddIntConstant( module, "OP_NO_SSLv2", SSL_OP_NO_SSLv2 );
    PyModule_AddIntConstant( module, "OP_NO_SSLv3", SSL_OP_NO_SSLv3 );
    PyModule_AddIntConstant( module, "OP_NO_TLSv1", SSL_OP_NO_TLSv1 );

    /* SSL context constants */
    PyModule_AddIntConstant( module, "SSL_MODE_AUTO_RETRY",
                             SSL_MODE_AUTO_RETRY );
    PyModule_AddIntConstant( module, "SSL_MODE_ENABLE_PARTIAL_WRITE",
                             SSL_MODE_ENABLE_PARTIAL_WRITE );

    /* More SSL option constants */
    PyModule_AddIntConstant( module, "OP_MICROSOFT_SESS_ID_BUG",
                             SSL_OP_MICROSOFT_SESS_ID_BUG );
    PyModule_AddIntConstant( module, "OP_NETSCAPE_CHALLENGE_BUG",
                             SSL_OP_NETSCAPE_CHALLENGE_BUG );
    PyModule_AddIntConstant( module, "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG",
                             SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG );
    PyModule_AddIntConstant( module, "OP_SSLREF2_REUSE_CERT_TYPE_BUG",
                             SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG );
    PyModule_AddIntConstant( module, "OP_MICROSOFT_BIG_SSLV3_BUFFER",
                             SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER );
    PyModule_AddIntConstant( module, "OP_MSIE_SSLV2_RSA_PADDING",
                             SSL_OP_MSIE_SSLV2_RSA_PADDING );
    PyModule_AddIntConstant( module, "OP_SSLEAY_080_CLIENT_DH_BUG",
                             SSL_OP_SSLEAY_080_CLIENT_DH_BUG );
    PyModule_AddIntConstant( module, "OP_TLS_D5_BUG", SSL_OP_TLS_D5_BUG );
    PyModule_AddIntConstant( module, "OP_TLS_BLOCK_PADDING_BUG",
                             SSL_OP_TLS_BLOCK_PADDING_BUG );
//    PyModule_AddIntConstant(module, "OP_DONT_INSERT_EMPTY_FRAGMENTS", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    PyModule_AddIntConstant( module, "OP_ALL", SSL_OP_ALL );
    PyModule_AddIntConstant( module, "OP_NO_QUERY_MTU",
                                 SSL_OP_NO_QUERY_MTU );
    PyModule_AddIntConstant( module, "OP_COOKIE_EXCHANGE",
                                 SSL_OP_COOKIE_EXCHANGE );
//    PyModule_AddIntConstant(module, "OP_CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE);
    PyModule_AddIntConstant( module, "OP_TLS_ROLLBACK_BUG",
                             SSL_OP_TLS_ROLLBACK_BUG );
    PyModule_AddIntConstant( module, "OP_PKCS1_CHECK_1",
                             SSL_OP_PKCS1_CHECK_1 );
    PyModule_AddIntConstant( module, "OP_PKCS1_CHECK_2",
                             SSL_OP_PKCS1_CHECK_2 );
    PyModule_AddIntConstant( module, "OP_NETSCAPE_CA_DN_BUG",
                             SSL_OP_NETSCAPE_CA_DN_BUG );
    PyModule_AddIntConstant( module, "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG",
                             SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG );

    /* Session constants */
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_OFF",
                             SSL_SESS_CACHE_OFF );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_CLIENT",
                             SSL_SESS_CACHE_CLIENT );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_SERVER",
                             SSL_SESS_CACHE_SERVER );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_BOTH",
                             SSL_SESS_CACHE_BOTH );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_NO_AUTO_CLEAR",
                             SSL_SESS_CACHE_NO_AUTO_CLEAR );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_NO_INTERNAL_LOOKUP",
                             SSL_SESS_CACHE_NO_INTERNAL_LOOKUP );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_NO_INTERNAL_STORE",
                             SSL_SESS_CACHE_NO_INTERNAL_STORE );
    PyModule_AddIntConstant( module, "SSL_SESS_CACHE_NO_INTERNAL_STORE",
                             SSL_SESS_CACHE_NO_INTERNAL_STORE );



    /* SSL Shutdown constants */
    PyModule_AddIntConstant( module, "SENT_SHUTDOWN", SSL_SENT_SHUTDOWN );
    PyModule_AddIntConstant( module, "RECEIVED_SHUTDOWN",
                             SSL_RECEIVED_SHUTDOWN );

    dict = PyModule_GetDict( module );
    if ( !init_ssl_context( dict ) )
        goto error;
    if ( !init_ssl_connection( dict ) )
        goto error;
    if ( !init_ssl_session( dict ) )
        goto error;

  error:
    ;
}
