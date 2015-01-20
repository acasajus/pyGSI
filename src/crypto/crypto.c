#include <Python.h>
#include <openssl/x509_vfy.h>
#define crypto_MODULE
#include "crypto.h"

static char crypto_doc[] = "\n\
Main file of crypto sub module.\n\
See the file RATIONALE for a short explanation of why this module was written.\n\
";

void **ssl_API;

PyObject *crypto_Error;

static int
global_passphrase_callback( char *buf, int len, int rwflag, void *cb_arg )
{
    PyObject *func, *argv, *ret;
    int nchars;

    func = ( PyObject * ) cb_arg;
    argv = Py_BuildValue( "(i)", rwflag );
    ret = PyEval_CallObject( func, argv );
    Py_DECREF( argv );
    if ( ret == NULL )
        return 0;
    if ( !PyString_Check( ret ) )
    {
        PyErr_SetString( PyExc_ValueError, "String expected" );
        return 0;
    }
    nchars = (int)PyString_Size( ret );
    if ( nchars > len )
        nchars = len;
    strncpy( buf, PyString_AsString( ret ), nchars );
    return nchars;
}

static char crypto_load_privatekey_doc[] = "\n\
Load a private key from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type       - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             buffer     - The buffer the key is stored in\n\
             passphrase - (optional) if encrypted PEM format, this can be\n\
                          either the passphrase to use, or a callback for\n\
                          providing the passphrase.\n\
Returns:   The PKey object\n\
";

static PyObject *
crypto_load_privatekey( PyObject * spam, PyObject * args )
{
    crypto_PKeyObj *crypto_PKey_New( EVP_PKEY *, int );
    int type, len;
    char *buffer;
    PyObject *pw = NULL;
    pem_password_cb *cb = NULL;
    void *cb_arg = NULL;
    BIO *bio;
    EVP_PKEY *pkey;

    if ( !PyArg_ParseTuple
         ( args, "is#|O:load_privatekey", &type, &buffer, &len, &pw ) )
        return NULL;

    if ( pw != NULL )
    {
        if ( PyString_Check( pw ) )
        {
            cb = NULL;
            cb_arg = PyString_AsString( pw );
        }
        else if ( PyCallable_Check( pw ) )
        {
            cb = global_passphrase_callback;
            cb_arg = pw;
        }
        else if ( PyObject_IsTrue( pw ) )
        {
            PyErr_SetString( PyExc_TypeError,
                             "Last argument must be string or callable" );
            return NULL;
        }
    }

    bio = BIO_new_mem_buf( buffer, len );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        pkey = PEM_read_bio_PrivateKey( bio, NULL, cb, cb_arg );
        break;

    case X509_FILETYPE_ASN1:
        pkey = d2i_PrivateKey_bio( bio, NULL );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }
    BIO_free( bio );

    if ( pkey == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return ( PyObject * ) crypto_PKey_New( pkey, 1 );
}

static char crypto_dump_privatekey_doc[] = "\n\
Dump a private key to a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type       - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             pkey       - The PKey to dump\n\
             cipher     - (optional) if encrypted PEM format, the cipher to\n\
                          use\n\
             passphrase - (optional) if encrypted PEM format, this can be either\n\
                          the passphrase to use, or a callback for providing the\n\
                          passphrase.\n\
Returns:   The buffer with the dumped key in\n\
";

static PyObject *
crypto_dump_privatekey( PyObject * spam, PyObject * args )
{
    int type, ret;
    long buf_len;
    char *temp;
    PyObject *buffer;
    char *cipher_name = NULL;
    const EVP_CIPHER *cipher = NULL;
    PyObject *pw = NULL;
    pem_password_cb *cb = NULL;
    void *cb_arg = NULL;
    BIO *bio;
    crypto_PKeyObj *pkey;

    if ( !PyArg_ParseTuple( args, "iO!|sO:dump_privatekey", &type,
                            &crypto_PKey_Type, &pkey, &cipher_name, &pw ) )
        return NULL;

    if ( cipher_name != NULL && pw == NULL )
    {
        PyErr_SetString( PyExc_ValueError, "Illegal number of arguments" );
        return NULL;
    }
    if ( cipher_name != NULL )
    {
        cipher = EVP_get_cipherbyname( cipher_name );
        if ( cipher == NULL )
        {
            PyErr_SetString( PyExc_ValueError, "Invalid cipher name" );
            return NULL;
        }
        if ( PyString_Check( pw ) )
        {
            cb = NULL;
            cb_arg = PyString_AsString( pw );
        }
        else if ( PyCallable_Check( pw ) )
        {
            cb = global_passphrase_callback;
            cb_arg = pw;
        }
        else
        {
            PyErr_SetString( PyExc_TypeError,
                             "Last argument must be string or callable" );
            return NULL;
        }
    }

    bio = BIO_new( BIO_s_mem(  ) );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        ret =
            PEM_write_bio_PrivateKey( bio, pkey->pkey, cipher, NULL, 0, cb,
                                      cb_arg );
        if ( PyErr_Occurred(  ) )
        {
            BIO_free( bio );
            return NULL;
        }
        break;

    case X509_FILETYPE_ASN1:
        ret = i2d_PrivateKey_bio( bio, pkey->pkey );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }

    if ( ret == 0 )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }

    buf_len = BIO_get_mem_data( bio, &temp );
    buffer = PyString_FromStringAndSize( temp, buf_len );
    BIO_free( bio );

    return buffer;
}

static char crypto_dump_publickey_doc[] = "\n\
Dump a public key to a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type       - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             pkey       - The PKey to dump\n\
Returns:   The buffer with the dumped key in\n\
";

static PyObject *
crypto_dump_publickey( PyObject * spam, PyObject * args )
{
    int type, ret;
    long buf_len;
    char *temp;
    PyObject *buffer;
    BIO *bio;
    crypto_PKeyObj *pkey;

    if ( !PyArg_ParseTuple( args, "iO!:dump_privatekey", &type,
                            &crypto_PKey_Type, &pkey ) )
        return NULL;

    bio = BIO_new( BIO_s_mem(  ) );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        ret = PEM_write_bio_PUBKEY( bio, pkey->pkey );
        if ( PyErr_Occurred(  ) )
        {
            BIO_free( bio );
            return NULL;
        }
        break;

    case X509_FILETYPE_ASN1:
        ret = i2d_PUBKEY_bio( bio, pkey->pkey );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }

    if ( ret == 0 )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }

    buf_len = BIO_get_mem_data( bio, &temp );
    buffer = PyString_FromStringAndSize( temp, buf_len );
    BIO_free( bio );

    return buffer;
}

static char crypto_load_crl_doc[] = "\n\
Load a crl from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type   - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             buffer - The buffer the crl is stored in\n\
Returns:   The X509CRL object\n\
";

static PyObject *
crypto_load_crl( PyObject * spam, PyObject * args )
{
    int type, len;
    char *buffer;
    BIO *bio;
    X509_CRL *crl;

    if ( !PyArg_ParseTuple
         ( args, "is#:load_crl", &type, &buffer, &len ) )
        return NULL;

    bio = BIO_new_mem_buf( buffer, len );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
    	crl = PEM_read_bio_X509_CRL( bio, NULL, NULL, NULL );
        break;

    case X509_FILETYPE_ASN1:
    	crl = d2i_X509_CRL_bio( bio, NULL );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }
    BIO_free( bio );

    if ( crl == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return ( PyObject * ) crypto_X509CRL_New( crl, 1 );
}



static char crypto_load_certificate_doc[] = "\n\
Load a certificate from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type   - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             buffer - The buffer the certificate is stored in\n\
Returns:   The X509 object\n\
";

static PyObject *
crypto_load_certificate( PyObject * spam, PyObject * args )
{
    crypto_X509Obj *crypto_X509_New( X509 *, int );
    int type, len;
    char *buffer;
    BIO *bio;
    X509 *cert;

    if ( !PyArg_ParseTuple
         ( args, "is#:load_certificate", &type, &buffer, &len ) )
        return NULL;

    bio = BIO_new_mem_buf( buffer, len );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        cert = PEM_read_bio_X509( bio, NULL, NULL, NULL );
        break;

    case X509_FILETYPE_ASN1:
        cert = d2i_X509_bio( bio, NULL );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }
    BIO_free( bio );

    if ( cert == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return ( PyObject * ) crypto_X509_New( cert, 1 );
}

static char crypto_load_certificate_chain_doc[] = "\n\
Load a certificate chain from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type   - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             buffer - The buffer the certificate chain is stored in\n\
Returns: List with X509 objects\n\
";

static PyObject *
crypto_load_certificate_chain( PyObject * spam, PyObject * args )
{
    crypto_X509Obj *crypto_X509_New( X509 *, int );
    int type, len;
    char *buffer;
    unsigned long err;
    PyObject *pyCertList, *pyCert;
    BIO *bio;
    X509 *cert;

    if ( !PyArg_ParseTuple
         ( args, "is#:load_certificate_chain", &type, &buffer, &len ) )
        return NULL;

    pyCertList = PyList_New( 0 );
    if ( !pyCertList )
        return NULL;

    bio = BIO_new_mem_buf( buffer, len );
    do
    {
        switch ( type )
        {
        case X509_FILETYPE_PEM:
            cert = PEM_read_bio_X509( bio, NULL, NULL, NULL );
            break;

        case X509_FILETYPE_ASN1:
            cert = d2i_X509_bio( bio, NULL );
            break;

        default:
            PyErr_SetString( PyExc_ValueError,
                             "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
            BIO_free( bio );
            Py_DECREF( pyCertList );
            return NULL;
        }

        if ( cert != NULL )
        {
            pyCert = ( PyObject * ) crypto_X509_New( cert, 1 );
            err = PyList_Append( pyCertList, pyCert );
            Py_DECREF( pyCert );
            if ( -1 == err )
            {
                BIO_free( bio );
                Py_DECREF( pyCertList );
                return NULL;
            }
        }
    }
    while ( cert );

    BIO_free( bio );
    //Ignore no start line error when loading a chain
    err = ERR_peek_last_error(  );
    if ( ERR_GET_LIB( err ) == ERR_LIB_PEM
         && ERR_GET_REASON( err ) == PEM_R_NO_START_LINE )
        ERR_clear_error(  );
    else
    {
        Py_DECREF( pyCertList );
        exception_from_error_queue(  );
        return NULL;
    }

    return pyCertList;
}

static char crypto_dump_certificate_doc[] = "\n\
Dump a certificate to a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             cert - The certificate to dump\n\
Returns:   The buffer with the dumped certificate in\n\
";

static PyObject *
crypto_dump_certificate( PyObject * spam, PyObject * args )
{
    int type, ret;
    long buf_len;
    char *temp;
    PyObject *buffer;
    BIO *bio;
    crypto_X509Obj *cert;

    if ( !PyArg_ParseTuple( args, "iO!:dump_certificate", &type,
                            &crypto_X509_Type, &cert ) )
        return NULL;

    bio = BIO_new( BIO_s_mem(  ) );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        ret = PEM_write_bio_X509( bio, cert->x509 );
        break;

    case X509_FILETYPE_ASN1:
        ret = i2d_X509_bio( bio, cert->x509 );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }

    if ( ret == 0 )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }

    buf_len = BIO_get_mem_data( bio, &temp );
    buffer = PyString_FromStringAndSize( temp, buf_len );
    BIO_free( bio );

    return buffer;
}

static char crypto_load_certificate_request_doc[] = "\n\
Load a certificate request from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type   - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             buffer - The buffer the certificate request is stored in\n\
Returns:   The X509Req object\n\
";

static PyObject *
crypto_load_certificate_request( PyObject * spam, PyObject * args )
{
    crypto_X509ReqObj *crypto_X509Req_New( X509_REQ *, int );
    int type, len;
    char *buffer;
    BIO *bio;
    X509_REQ *req;

    if ( !PyArg_ParseTuple
         ( args, "is#:load_certificate_request", &type, &buffer, &len ) )
        return NULL;

    bio = BIO_new_mem_buf( buffer, len );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        req = PEM_read_bio_X509_REQ( bio, NULL, NULL, NULL );
        break;

    case X509_FILETYPE_ASN1:
        req = d2i_X509_REQ_bio( bio, NULL );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }
    BIO_free( bio );

    if ( req == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return ( PyObject * ) crypto_X509Req_New( req, 1 );
}

static char crypto_dump_certificate_request_doc[] = "\n\
Dump a certificate request to a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             type - The file type (one of FILETYPE_PEM, FILETYPE_ASN1)\n\
             req  - The certificate request to dump\n\
Returns:   The buffer with the dumped certificate request in\n\
";

static PyObject *
crypto_dump_certificate_request( PyObject * spam, PyObject * args )
{
    int type, ret;
    long buf_len;
    char *temp;
    PyObject *buffer;
    BIO *bio;
    crypto_X509ReqObj *req;

    if ( !PyArg_ParseTuple( args, "iO!:dump_certificate_request", &type,
                            &crypto_X509Req_Type, &req ) )
        return NULL;

    bio = BIO_new( BIO_s_mem(  ) );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        ret = PEM_write_bio_X509_REQ( bio, req->x509_req );
        break;

    case X509_FILETYPE_ASN1:
        ret = i2d_X509_REQ_bio( bio, req->x509_req );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        BIO_free( bio );
        return NULL;
    }

    if ( ret == 0 )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }

    buf_len = BIO_get_mem_data( bio, &temp );
    buffer = PyString_FromStringAndSize( temp, buf_len );
    BIO_free( bio );

    return buffer;
}

static char crypto_load_pkcs7_data_doc[] = "\n\
Load pkcs7 data from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The argument tuple, should be:\n\
             type - The file type (one of FILETYPE_PEM or FILETYPE_ASN1)\n\
             buffer - The buffer with the pkcs7 data.\n\
Returns: The PKCS7 object\n\
";

static PyObject *
crypto_load_pkcs7_data( PyObject * spam, PyObject * args )
{
    int type, len;
    char *buffer;
    BIO *bio;
    PKCS7 *pkcs7 = NULL;

    if ( !PyArg_ParseTuple
         ( args, "is#:load_pkcs7_data", &type, &buffer, &len ) )
        return NULL;

    /*
     * Try to read the pkcs7 data from the bio
     */
    bio = BIO_new_mem_buf( buffer, len );
    switch ( type )
    {
    case X509_FILETYPE_PEM:
        pkcs7 = PEM_read_bio_PKCS7( bio, NULL, NULL, NULL );
        break;

    case X509_FILETYPE_ASN1:
        pkcs7 = d2i_PKCS7_bio( bio, NULL );
        break;

    default:
        PyErr_SetString( PyExc_ValueError,
                         "type argument must be FILETYPE_PEM or FILETYPE_ASN1" );
        return NULL;
    }
    BIO_free( bio );

    /*
     * Check if we got a PKCS7 structure
     */
    if ( pkcs7 == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return ( PyObject * ) crypto_PKCS7_New( pkcs7, 1 );
}

static char crypto_load_pkcs12_doc[] = "\n\
Load a PKCS12 object from a buffer\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             buffer - The buffer the certificate is stored in\n\
             passphrase (Optional) - The password to decrypt the PKCS12 lump\n\
Returns:   The PKCS12 object\n\
";

static PyObject *
crypto_load_pkcs12( PyObject * spam, PyObject * args )
{
    crypto_PKCS12Obj *crypto_PKCS12_New( PKCS12 *, char * );
    int len;
    char *buffer, *passphrase = NULL;
    BIO *bio;
    PKCS12 *p12;

    if ( !PyArg_ParseTuple
         ( args, "s#|s:load_pkcs12", &buffer, &len, &passphrase ) )
        return NULL;

    bio = BIO_new_mem_buf( buffer, len );
    if ( ( p12 = d2i_PKCS12_bio( bio, NULL ) ) == NULL )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }
    BIO_free( bio );

    return ( PyObject * ) crypto_PKCS12_New( p12, passphrase );
}

static char crypto_add_x509_extension_alias_doc[] = "\n\
Set an alias from a previous extension\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty or, optionally\n\
             new nid - int with the new nid\n\
			 old nid - int with the nid to alias\n\
Returns: None\n\
";

static PyObject *
crypto_add_x509_extension_alias( PyObject * spam, PyObject * args )
{
    int nid, old_nid;

    if ( !PyArg_ParseTuple
         ( args, "ii:add_x509_extension_alias", &nid, &old_nid ) )
        return NULL;

    X509V3_EXT_add_alias( nid, old_nid );

    Py_RETURN_NONE;
}


static char crypto_create_oid_doc[] = "\n\
Create a new ssl OID \n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty or, optionally\n\
             OID - string with the oid.\n\
			 shortName - string with the short name.\n\
			 longName - string with the long name.\n\
Returns:   nid id\n\
";

static PyObject *
crypto_create_oid( PyObject * spam, PyObject * args )
{
    char *oid, *sn, *ln;
    int nid;

    if ( !PyArg_ParseTuple( args, "sss:create_nid", &oid, &sn, &ln ) )
        return NULL;

    nid = OBJ_create( oid, sn, ln );
    if ( !nid )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return PyInt_FromLong( nid );
}

static char crypto_X509Store_doc[] = "\n\
Create a new X509 store \n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty\n\
Returns:   X509 store\n\
";

static PyObject *
crypto_X509Store( PyObject * spam, PyObject * args )
{

    if ( !PyArg_ParseTuple( args, ":X509Store" ) )
            return NULL;

    return ( PyObject * ) crypto_X509Store_New( X509_STORE_new(  ), 1 );
}

static char crypto_X509_doc[] = "\n\
The factory function inserted in the module dictionary to create X509\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The X509 object\n\
";

static PyObject *
crypto_X509( PyObject * spam, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":X509" ) )
        return NULL;

    return ( PyObject * ) crypto_X509_New( X509_new(  ), 1 );
}

static char crypto_X509Name_doc[] = "\n\
The factory function inserted in the module dictionary as a copy\n\
constructor for X509Name objects.\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             name - An X509Name object to copy\n\
Returns:   The X509Name object\n\
";

static PyObject *
crypto_X509Name( PyObject * spam, PyObject * args )
{
    crypto_X509NameObj *name;

    if ( !PyArg_ParseTuple
         ( args, "O!:X509Name", &crypto_X509Name_Type, &name ) )
        return NULL;

    return ( PyObject * )
        crypto_X509Name_New( X509_NAME_dup( name->x509_name ), 1 );
}

static char crypto_X509Req_doc[] = "\n\
The factory function inserted in the module dictionary to create X509Req\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The X509Req object\n\
";

static PyObject *
crypto_X509Req( PyObject * spam, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":X509Req" ) )
        return NULL;

    return ( PyObject * ) crypto_X509Req_New( X509_REQ_new(  ), 1 );
}

static char crypto_PKey_doc[] = "\n\
The factory function inserted in the module dictionary to create PKey\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The PKey object\n\
";

static PyObject *
crypto_PKey( PyObject * spam, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":PKey" ) )
        return NULL;

    return ( PyObject * ) crypto_PKey_New( EVP_PKEY_new(  ), 1 );
}

static char crypto_X509Extension_doc[] = "\n\
The factory function inserted in the module dictionary to create\n\
X509Extension objects.\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be\n\
             typename - extension name\n\
             value    - extension value\n\
Returns:   The X509Extension object\n\
";

static PyObject *
crypto_X509Extension( PyObject * spam, PyObject * args )
{
    char *type_name, *value;
		int val_length;

    if ( !PyArg_ParseTuple( args, "ss#:X509Extension", &type_name, &value, &val_length ) )
        return NULL;

    return ( PyObject * ) crypto_X509Extension_New( type_name, value, val_length);
}

static char crypto_NetscapeSPKI_doc[] = "\n\
The factory function inserted in the module dictionary to create NetscapeSPKI\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be empty or, optionally\n\
             enc - Base64 encoded NetscapeSPKI object.\n\
Returns:   The NetscapeSPKI object\n\
";

static PyObject *
crypto_NetscapeSPKI( PyObject * spam, PyObject * args )
{
    char *enc = NULL;
    int enc_len = -1;
    NETSCAPE_SPKI *spki;

    if ( !PyArg_ParseTuple( args, "|s#:NetscapeSPKI", &enc, &enc_len ) )
        return NULL;

    if ( enc_len >= 0 )
        spki = NETSCAPE_SPKI_b64_decode( enc, enc_len );
    else
        spki = NETSCAPE_SPKI_new(  );
    if ( spki == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    return ( PyObject * ) crypto_NetscapeSPKI_New( spki, 1 );
}

static char crypto_X509CRL_doc[] = "\n\
The factory function inserted in the module dictionary as a copy\n\
constructor for X509CRL objects.\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             crl - An X509CRL object to copy\n\
Returns:   The X509CRL object\n\
";

static PyObject *
crypto_X509CRL( PyObject * spam, PyObject * args )
{
    crypto_X509CRLObj *crl;

    if ( !PyArg_ParseTuple
         ( args, "O!:X509CRL", &crypto_X509CRL_Type, &crl ) )
        return NULL;

    return ( PyObject * )
        crypto_X509CRL_New( X509_CRL_dup( crl->crl ), 1 );
}

/* Methods in the GSI.crypto module (i.e. none) */
static PyMethodDef crypto_methods[] = {
    /* Module functions */
    {"load_privatekey", ( PyCFunction ) crypto_load_privatekey, METH_VARARGS,
     crypto_load_privatekey_doc},
    {"dump_privatekey", ( PyCFunction ) crypto_dump_privatekey, METH_VARARGS,
     crypto_dump_privatekey_doc},
    {"dump_publickey", ( PyCFunction ) crypto_dump_publickey, METH_VARARGS,
     crypto_dump_publickey_doc},
     {"load_crl", ( PyCFunction ) crypto_load_crl,
      METH_VARARGS,
      crypto_load_crl_doc},
     {"load_certificate", ( PyCFunction ) crypto_load_certificate,
     METH_VARARGS,
     crypto_load_certificate_doc},
    {"load_certificate_chain", ( PyCFunction ) crypto_load_certificate_chain,
     METH_VARARGS, crypto_load_certificate_chain_doc},
    {"dump_certificate", ( PyCFunction ) crypto_dump_certificate,
     METH_VARARGS,
     crypto_dump_certificate_doc},
    {"load_certificate_request",
     ( PyCFunction ) crypto_load_certificate_request, METH_VARARGS,
     crypto_load_certificate_request_doc},
    {"dump_certificate_request",
     ( PyCFunction ) crypto_dump_certificate_request, METH_VARARGS,
     crypto_dump_certificate_request_doc},
    {"load_pkcs7_data", ( PyCFunction ) crypto_load_pkcs7_data, METH_VARARGS,
     crypto_load_pkcs7_data_doc},
    {"load_pkcs12", ( PyCFunction ) crypto_load_pkcs12, METH_VARARGS,
     crypto_load_pkcs12_doc},
    {"create_oid", ( PyCFunction ) crypto_create_oid, METH_VARARGS,
     crypto_create_oid_doc},
    {"add_x509_extension_alias",
     ( PyCFunction ) crypto_add_x509_extension_alias, METH_VARARGS,
     crypto_add_x509_extension_alias_doc},
    {"asn1_loads", crypto_ASN1_loads, METH_VARARGS, "" },
    /* Factory functions */
    {"X509Store", ( PyCFunction ) crypto_X509Store, METH_VARARGS, crypto_X509Store_doc},
    {"X509", ( PyCFunction ) crypto_X509, METH_VARARGS, crypto_X509_doc},
    {"X509Name", ( PyCFunction ) crypto_X509Name, METH_VARARGS,
     crypto_X509Name_doc},
    {"X509Req", ( PyCFunction ) crypto_X509Req, METH_VARARGS,
     crypto_X509Req_doc},
    {"PKey", ( PyCFunction ) crypto_PKey, METH_VARARGS, crypto_PKey_doc},
    {"X509Extension", ( PyCFunction ) crypto_X509Extension, METH_VARARGS,
     crypto_X509Extension_doc},
    {"NetscapeSPKI", ( PyCFunction ) crypto_NetscapeSPKI, METH_VARARGS,
     crypto_NetscapeSPKI_doc},
    {"X509CRL", ( PyCFunction ) crypto_X509CRL, METH_VARARGS,
      crypto_X509CRL_doc},
    {NULL, NULL}
};

/*
 * Initialize crypto sub module
 *
 * Arguments: None
 * Returns:   None
 */
void
initcrypto( void )
{
    static void *crypto_API[crypto_API_pointers];
    PyObject *c_api_object;
    PyObject *module, *dict;

    ERR_load_crypto_strings(  );
    OpenSSL_add_all_algorithms(  );
    initialize_python_datetime();

    if ( ( module =
           Py_InitModule3( "crypto", crypto_methods, crypto_doc ) ) == NULL )
        return;

    /* Initialize the C API pointer array */
    crypto_API[crypto_X509_New_NUM] = ( void * ) crypto_X509_New;
    crypto_API[crypto_X509Name_New_NUM] = ( void * ) crypto_X509Name_New;
    crypto_API[crypto_X509Req_New_NUM] = ( void * ) crypto_X509Req_New;
    crypto_API[crypto_X509Store_New_NUM] = ( void * ) crypto_X509Store_New;
    crypto_API[crypto_PKey_New_NUM] = ( void * ) crypto_PKey_New;
    crypto_API[crypto_X509Extension_New_NUM] =
        ( void * ) crypto_X509Extension_New;
    crypto_API[crypto_PKCS7_New_NUM] = ( void * ) crypto_PKCS7_New;
    crypto_API[crypto_NetscapeSPKI_New_NUM] =
        ( void * ) crypto_NetscapeSPKI_New;
    crypto_API[crypto_X509CRL_New_NUM] = ( void * ) crypto_X509CRL_New;

    c_api_object = PyCObject_FromVoidPtr( ( void * ) crypto_API, NULL );
    if ( c_api_object != NULL )
        PyModule_AddObject( module, "_C_API", c_api_object );

    crypto_Error = PyErr_NewException( "GSI.crypto.Error", NULL, NULL );
    if ( crypto_Error == NULL )
        goto error;
    if ( PyModule_AddObject( module, "Error", crypto_Error ) != 0 )
        goto error;

    PyModule_AddIntConstant( module, "FILETYPE_PEM", X509_FILETYPE_PEM );
    PyModule_AddIntConstant( module, "FILETYPE_ASN1", X509_FILETYPE_ASN1 );

    PyModule_AddIntConstant( module, "TYPE_RSA", crypto_TYPE_RSA );
    PyModule_AddIntConstant( module, "TYPE_DSA", crypto_TYPE_DSA );

    PyModule_AddIntConstant( module, "X509_CRL_CHECK",
                             X509_V_FLAG_CRL_CHECK );
    PyModule_AddIntConstant( module, "X509_CRL_CHECK_ALL",
                             X509_V_FLAG_CRL_CHECK_ALL );

    PyModule_AddIntConstant( module, "V_ASN1_ANY", V_ASN1_ANY );
    PyModule_AddIntConstant( module, "V_ASN1_BIT_STRING", V_ASN1_BIT_STRING );
    PyModule_AddIntConstant( module, "V_ASN1_BMPSTRING", V_ASN1_BMPSTRING );
    PyModule_AddIntConstant( module, "V_ASN1_BOOLEAN", V_ASN1_BOOLEAN );
    PyModule_AddIntConstant( module, "V_ASN1_ENUMERATED", V_ASN1_ENUMERATED );
    PyModule_AddIntConstant( module, "V_ASN1_GENERALIZEDTIME", V_ASN1_GENERALIZEDTIME );
    PyModule_AddIntConstant( module, "V_ASN1_GENERALSTRING", V_ASN1_GENERALSTRING );
    PyModule_AddIntConstant( module, "V_ASN1_GRAPHICSTRING", V_ASN1_GRAPHICSTRING );
    PyModule_AddIntConstant( module, "V_ASN1_IA5STRING", V_ASN1_IA5STRING );
    PyModule_AddIntConstant( module, "V_ASN1_INTEGER", V_ASN1_INTEGER );
    PyModule_AddIntConstant( module, "V_ASN1_NEG_ENUMERATED", V_ASN1_NEG_ENUMERATED );
    PyModule_AddIntConstant( module, "V_ASN1_NEG_INTEGER", V_ASN1_NEG_INTEGER );
    PyModule_AddIntConstant( module, "V_ASN1_NULL", V_ASN1_NULL );
    PyModule_AddIntConstant( module, "V_ASN1_NUMERICSTRING", V_ASN1_NUMERICSTRING );
    PyModule_AddIntConstant( module, "V_ASN1_OBJECT", V_ASN1_OBJECT );
    PyModule_AddIntConstant( module, "V_ASN1_OCTET_STRING", V_ASN1_OCTET_STRING );
    PyModule_AddIntConstant( module, "V_ASN1_OTHER", V_ASN1_OTHER );
    PyModule_AddIntConstant( module, "V_ASN1_PRINTABLESTRING", V_ASN1_PRINTABLESTRING );
    PyModule_AddIntConstant( module, "V_ASN1_SEQUENCE", V_ASN1_SEQUENCE );
    PyModule_AddIntConstant( module, "V_ASN1_SET", V_ASN1_SET );
    PyModule_AddIntConstant( module, "V_ASN1_T61STRING", V_ASN1_T61STRING );
    PyModule_AddIntConstant( module, "V_ASN1_UNIVERSALSTRING", V_ASN1_UNIVERSALSTRING );
    PyModule_AddIntConstant( module, "V_ASN1_UTCTIME", V_ASN1_UTCTIME );
    PyModule_AddIntConstant( module, "V_ASN1_UTF8STRING", V_ASN1_UTF8STRING );
    PyModule_AddIntConstant( module, "V_ASN1_VIDEOTEXSTRING", V_ASN1_VIDEOTEXSTRING );
    PyModule_AddIntConstant( module, "V_ASN1_VISIBLESTRING", V_ASN1_VISIBLESTRING );


    dict = PyModule_GetDict( module );
    if ( !init_crypto_x509( dict ) )
        goto error;
    if ( !init_crypto_x509name( dict ) )
        goto error;
    if ( !init_crypto_x509store( dict ) )
        goto error;
    if ( !init_crypto_x509req( dict ) )
        goto error;
    if ( !init_crypto_pkey( dict ) )
        goto error;
    if ( !init_crypto_x509extension( dict ) )
        goto error;
    if ( !init_crypto_pkcs7( dict ) )
        goto error;
    if ( !init_crypto_pkcs12( dict ) )
        goto error;
    if ( !init_crypto_netscape_spki( dict ) )
        goto error;
    if ( !init_crypto_x509CRL( dict ) )
        goto error;
    if ( !init_crypto_ASN1( dict ) )
        goto error;

  error:
    ;
}
