#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

/*
 * X.509 is a standard for digital certificates.  See e.g. the OpenSSL homepage
 * http://www.openssl.org/ for more information
 */

static char crypto_X509_get_version_doc[] = "\n\
Return version number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Version number as a Python integer\n\
";

static PyObject *
crypto_X509_get_version( crypto_X509Obj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_version" ) )
        return NULL;

    return PyInt_FromLong( ( long ) X509_get_version( self->x509 ) );
}

static char crypto_X509_set_version_doc[] = "\n\
Set version number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             version - The version number\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_version( crypto_X509Obj * self, PyObject * args )
{
    int version;

    if ( !PyArg_ParseTuple( args, "i:set_version", &version ) )
        return NULL;

    X509_set_version( self->x509, version );

    Py_RETURN_NONE;
}

static char crypto_X509_get_serial_number_doc[] = "\n\
Return serial number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Serial number as a Python integer\n\
";

static PyObject *
crypto_X509_get_serial_number( crypto_X509Obj * self, PyObject * args )
{
   ASN1_INTEGER *asn1_i;
   int length;
   PyObject *pySerial;
   unsigned char *cbuf;

   if ( !PyArg_ParseTuple( args, ":get_serial_number" ) )
      return NULL;

   asn1_i = X509_get_serialNumber( self->x509 );

   length = i2c_ASN1_INTEGER( asn1_i, NULL );
   if( !length )
      return PyString_FromString( "" );
   pySerial = PyString_FromStringAndSize( NULL, length );
   cbuf = (unsigned char*)PyString_AsString( pySerial );
   length = i2c_ASN1_INTEGER( asn1_i, &cbuf);

   return pySerial;
}

static char crypto_X509_set_serial_number_doc[] = "\n\
Set serial number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             serial - The serial number\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_serial_number( crypto_X509Obj * self, PyObject * args )
{
   const  unsigned char *serial;
   long serialLength;
   ASN1_INTEGER *asn1_i;

   if ( !PyArg_ParseTuple( args, "s#:set_serial_number", &serial, &serialLength ) )
      return NULL;

   asn1_i = X509_get_serialNumber( self->x509 );
   c2i_ASN1_INTEGER( &asn1_i, &serial, serialLength );

   Py_RETURN_NONE;
}

static char crypto_X509_get_issuer_doc[] = "\n\
Create an X509Name object for the issuer of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   An X509Name object\n\
";

static PyObject *
crypto_X509_get_issuer( crypto_X509Obj * self, PyObject * args )
{
    crypto_X509NameObj *pyname;
    X509_NAME *name;

    if ( !PyArg_ParseTuple( args, ":get_issuer" ) )
        return NULL;

    name = X509_get_issuer_name( self->x509 );
    pyname = crypto_X509Name_New( name, 0 );
    if ( pyname != NULL )
    {
        Py_INCREF( self );
    	pyname->parent_cert = ( PyObject * ) self;
    }
    return ( PyObject * ) pyname;
}

static char crypto_X509_check_issued_doc[] = "\n\
Check if the given certificate is the issuer\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
			- issuer - X509 object to check if it's issuer\n\
		Returns:   An X509Name object\n\
";

static PyObject *
crypto_X509_check_issued( crypto_X509Obj * self, PyObject * args )
{
    crypto_X509Obj *issuerCert;

    if ( !PyArg_ParseTuple
         ( args, "O!:check_issued", &crypto_X509_Type, &issuerCert ) )
        return NULL;

    if ( X509_check_issued( issuerCert->x509, self->x509 ) == X509_V_OK )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static char crypto_X509_set_issuer_doc[] = "\n\
Set the issuer of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             issuer - The issuer name\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_issuer( crypto_X509Obj * self, PyObject * args )
{
    crypto_X509NameObj *issuer;

    if ( !PyArg_ParseTuple( args, "O!:set_issuer", &crypto_X509Name_Type,
                            &issuer ) )
        return NULL;

    if ( !X509_set_issuer_name( self->x509, issuer->x509_name ) )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    Py_RETURN_NONE;
}

static char crypto_X509_get_subject_doc[] = "\n\
Create an X509Name object for the subject of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   An X509Name object\n\
";

static PyObject *
crypto_X509_get_subject( crypto_X509Obj * self, PyObject * args )
{
    crypto_X509NameObj *pyname;
    X509_NAME *name;

    if ( !PyArg_ParseTuple( args, ":get_subject" ) )
        return NULL;

    name = X509_get_subject_name( self->x509 );
    pyname = crypto_X509Name_New( name, 0 );
    if ( pyname != NULL )
    {
        Py_INCREF( self );
        pyname->parent_cert = ( PyObject * ) self;
    }
    return ( PyObject * ) pyname;
}

static char crypto_X509_set_subject_doc[] = "\n\
Set the subject of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             subject - The subject name\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_subject( crypto_X509Obj * self, PyObject * args )
{
    crypto_X509NameObj *subject;

    if ( !PyArg_ParseTuple( args, "O!:set_subject", &crypto_X509Name_Type,
                            &subject ) )
        return NULL;

    if ( !X509_set_subject_name( self->x509, subject->x509_name ) )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    Py_RETURN_NONE;
}

static char crypto_X509_get_pubkey_doc[] = "\n\
Get the public key of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The public key\n\
";

static PyObject *
crypto_X509_get_pubkey( crypto_X509Obj * self, PyObject * args )
{
    crypto_PKeyObj *crypto_PKey_New( EVP_PKEY *, int );
    EVP_PKEY *pkey;

    if ( !PyArg_ParseTuple( args, ":get_pubkey" ) )
        return NULL;

    if ( ( pkey = X509_get_pubkey( self->x509 ) ) == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return ( PyObject * ) crypto_PKey_New( pkey, 1 );
}

static char crypto_X509_set_pubkey_doc[] = "\n\
Set the public key of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             pkey - The public key\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_pubkey( crypto_X509Obj * self, PyObject * args )
{
    crypto_PKeyObj *pkey;

    if ( !PyArg_ParseTuple
         ( args, "O!:set_pubkey", &crypto_PKey_Type, &pkey ) )
        return NULL;

    if ( !X509_set_pubkey( self->x509, pkey->pkey ) )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    Py_RETURN_NONE;
}

static char crypto_X509_gmtime_adj_notBefore_doc[] = "\n\
Adjust the time stamp for when the certificate starts being valid\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             i - The adjustment\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_gmtime_adj_notBefore( crypto_X509Obj * self, PyObject * args )
{
    long i;

    if ( !PyArg_ParseTuple( args, "l:gmtime_adj_notBefore", &i ) )
        return NULL;

    X509_gmtime_adj( X509_get_notBefore( self->x509 ), i );

    Py_RETURN_NONE;
}

static char crypto_X509_gmtime_adj_notAfter_doc[] = "\n\
Adjust the time stamp for when the certificate stops being valid\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             i - The adjustment\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_gmtime_adj_notAfter( crypto_X509Obj * self, PyObject * args )
{
    long i;

    if ( !PyArg_ParseTuple( args, "l:gmtime_adj_notAfter", &i ) )
        return NULL;

    X509_gmtime_adj( X509_get_notAfter( self->x509 ), i );

    Py_RETURN_NONE;
}

static char crypto_X509_sign_doc[] = "\n\
Sign the certificate using the supplied key and digest\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             pkey   - The key to sign with\n\
             digest - The message digest to use\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_sign( crypto_X509Obj * self, PyObject * args )
{
    crypto_PKeyObj *pkey;
    char *digest_name;
    const EVP_MD *digest;

    if ( !PyArg_ParseTuple( args, "O!s:sign", &crypto_PKey_Type, &pkey,
                            &digest_name ) )
        return NULL;

    if ( ( digest = EVP_get_digestbyname( digest_name ) ) == NULL )
    {
        PyErr_SetString( PyExc_ValueError, "No such digest method" );
        return NULL;
    }

    if ( !X509_sign( self->x509, pkey->pkey, digest ) )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    Py_RETURN_NONE;
}

static char crypto_X509_verify_pkey_is_issuer_doc[] = "\n\
Verify if the certificate was issued with the key\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             pkey   - The key that issued\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_verify_pkey_is_issuer( crypto_X509Obj * self, PyObject * args )
{
    crypto_PKeyObj *pkey;

    if ( !PyArg_ParseTuple( args, "O!:verify", &crypto_PKey_Type, &pkey ) )
        return NULL;

    if ( X509_verify( self->x509, pkey->pkey ) )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static char crypto_X509_has_expired_doc[] = "\n\
Check whether the certificate has expired.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if the certificate has expired, false otherwise\n\
";

static PyObject *
crypto_X509_has_expired( crypto_X509Obj * self, PyObject * args )
{
    time_t tnow;

    if ( !PyArg_ParseTuple( args, ":has_expired" ) )
        return NULL;

    tnow = time( NULL );
    if ( ASN1_UTCTIME_cmp_time_t( X509_get_notAfter( self->x509 ), tnow ) <
         0 )
    	Py_RETURN_TRUE;
    else
    	Py_RETURN_FALSE;
}

static char crypto_X509_get_not_after_doc[] = "\n\
Get the not after date.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   not after datetime or None if error\n\
";

static PyObject *
crypto_X509_get_not_after( crypto_X509Obj * self, PyObject * args )
{
    ASN1_TIME *notafter;

    if ( !PyArg_ParseTuple( args, ":get_not_after" ) )
        return NULL;

    notafter = X509_get_notAfter( self->x509 );

    return convertASN1_TIMEToDateTime( notafter );
}

static char crypto_X509_get_not_before_doc[] = "\n\
Get the not before date.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   not before datetime or None if error\n\
";

static PyObject *
crypto_X509_get_not_before( crypto_X509Obj * self, PyObject * args )
{
    ASN1_TIME *notbefore;

    if ( !PyArg_ParseTuple( args, ":get_not_before" ) )
        return NULL;

    notbefore = X509_get_notBefore( self->x509 );

    return convertASN1_TIMEToDateTime( notbefore );
}

static char crypto_X509_subject_name_hash_doc[] = "\n\
Return the hash of the X509 subject.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The hash of the subject\n\
";

static PyObject *
crypto_X509_subject_name_hash( crypto_X509Obj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":subject_name_hash" ) )
        return NULL;

    return PyLong_FromLong( X509_subject_name_hash( self->x509 ) );
}

static char crypto_X509_digest_doc[] = "\n\
Return the digest of the X509 object.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The digest of the object\n\
";

static PyObject *
crypto_X509_digest( crypto_X509Obj * self, PyObject * args )
{
    unsigned char fp[EVP_MAX_MD_SIZE];
    char *tmp;
    char *digest_name;
    unsigned int len, i;
    PyObject *ret;
    const EVP_MD *digest;

    if ( !PyArg_ParseTuple( args, "s:digest", &digest_name ) )
        return NULL;

    if ( ( digest = EVP_get_digestbyname( digest_name ) ) == NULL )
    {
        PyErr_SetString( PyExc_ValueError, "No such digest method" );
        return NULL;
    }

    if ( !X509_digest( self->x509, digest, fp, &len ) )
    {
        exception_from_error_queue(  );
    }
    tmp = malloc( 3 * len + 1 );
    memset( tmp, 0, 3 * len + 1 );
    for ( i = 0; i < len; i++ )
    {
        sprintf( tmp + i * 3, "%02X:", fp[i] );
    }
    tmp[3 * len - 1] = 0;
    ret = PyString_FromStringAndSize( tmp, 3 * len - 1 );
    free( tmp );
    return ret;
}

static char crypto_X509_get_extensions_doc[] = "\n\
Get extensions from the certificate.\n\
\n\
Arguments: self - X509 object\n\
           args - The Python argument tuple, should be: empty \n\
Returns:   None\n\
";

static PyObject *
crypto_X509_get_extensions( crypto_X509Obj * self, PyObject * args )
{
    PyObject *extList;
    crypto_X509ExtensionObj *pyext;
    X509_EXTENSION *ext;
    int extNum, i;

    if ( !PyArg_ParseTuple( args, ":get_extensions" ) )
        return NULL;

    extNum = X509_get_ext_count( self->x509 );
    if ( extNum < 0 )
        extNum = 0;
    extList = PyList_New( extNum );
    for ( i = 0; i < extNum; i++ )
    {
        ext = X509_get_ext( self->x509, i );
        if ( ext )
        {
            pyext =
                PyObject_New( crypto_X509ExtensionObj,
                              &crypto_X509Extension_Type );
            if ( !pyext )
            {
                Py_DECREF( extList );
                PyErr_SetString( PyExc_OSError,
                                 "Can't create extension object" );
                return NULL;
            }
            pyext->x509_extension = ext;
            pyext->dealloc = 0;
            PyList_SetItem( extList, i, ( PyObject * ) pyext );
        }
        else
        {
            Py_DECREF( extList );
            exception_from_error_queue(  );
            return NULL;
        }
    }
    return extList;
}

static char crypto_X509_add_extensions_doc[] = "\n\
Add extensions to the certificate.\n\
\n\
Arguments: self - X509 object\n\
           args - The Python argument tuple, should be:\n\
             extensions - a sequence of X509Extension objects\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_add_extensions( crypto_X509Obj * self, PyObject * args )
{
    PyObject *extList, *seq;
    crypto_X509ExtensionObj *ext;
    long nr_of_extensions, i;

    if ( !PyArg_ParseTuple( args, "O:add_extensions", &extList ) )
        return NULL;

    seq = PySequence_Fast( extList, "Expected a sequence" );
    if ( seq == NULL )
        return NULL;

    nr_of_extensions = PySequence_Fast_GET_SIZE( seq );

    /*
     * ADRIFIX: Removed Py_DECREF( extList ) because it's a param
     * 			seq comes from PySequence_Fast and it's a New ref
     */

    for ( i = 0; i < nr_of_extensions; i++ )
    {
        ext =
            ( crypto_X509ExtensionObj * ) PySequence_Fast_GET_ITEM( seq, i );
        if ( !crypto_X509Extension_Check( ext ) )
        {
            Py_DECREF( seq );
            PyErr_SetString( PyExc_ValueError,
                             "One of the elements is not an X509Extension" );
            return NULL;
        }
        if ( !X509_add_ext( self->x509, ext->x509_extension, -1 ) )
        {
            Py_DECREF( seq );
            exception_from_error_queue(  );
            return NULL;
        }
    }

    Py_DECREF( seq );
    Py_RETURN_NONE;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_X509_##name, METH_VARARGS, crypto_X509_##name##_doc }
static PyMethodDef crypto_X509_methods[] = {
    ADD_METHOD( get_version ),
    ADD_METHOD( set_version ),
    ADD_METHOD( get_serial_number ),
    ADD_METHOD( set_serial_number ),
    ADD_METHOD( get_issuer ),
    ADD_METHOD( set_issuer ),
    ADD_METHOD( check_issued ),
    ADD_METHOD( get_subject ),
    ADD_METHOD( set_subject ),
    ADD_METHOD( get_pubkey ),
    ADD_METHOD( set_pubkey ),
    ADD_METHOD( gmtime_adj_notBefore ),
    ADD_METHOD( gmtime_adj_notAfter ),
    ADD_METHOD( sign ),
    ADD_METHOD( verify_pkey_is_issuer ),
    ADD_METHOD( has_expired ),
    ADD_METHOD( subject_name_hash ),
    ADD_METHOD( digest ),
    ADD_METHOD( add_extensions ),
    ADD_METHOD( get_extensions ),
    ADD_METHOD( get_not_after ),
    ADD_METHOD( get_not_before ),
    {NULL, NULL}
};

#undef ADD_METHOD


/*
 * Constructor for X509 objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" X509 certificate object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" X509 object
 * Returns:   The newly created X509 object
 */
crypto_X509Obj *
crypto_X509_New( X509 * cert, int dealloc )
{
    crypto_X509Obj *self;

    self = PyObject_New( crypto_X509Obj, &crypto_X509_Type );

    if ( self == NULL )
        return NULL;

    self->x509 = cert;
    self->dealloc = dealloc;

    return self;
}

/*
 * Deallocate the memory used by the X509 object
 *
 * Arguments: self - The X509 object
 * Returns:   None
 */
static void
crypto_X509_dealloc( crypto_X509Obj * self )
{
    /* Sometimes we don't have to dealloc the "real" X509 pointer ourselves */
    if ( self->dealloc && self->x509 )
    {
        X509_free( self->x509 );
        self->x509 = NULL;
    }

    PyObject_Del( self );
}

/*
 * Find attribute
 *
 * Arguments: self - The X509 object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
crypto_X509_getattr( crypto_X509Obj * self, char *name )
{
    return Py_FindMethod( crypto_X509_methods, ( PyObject * ) self, name );
}

PyTypeObject crypto_X509_Type = {
    PyObject_HEAD_INIT( NULL ) 0,
    "X509",
    sizeof( crypto_X509Obj ),
    0,
    ( destructor ) crypto_X509_dealloc,
    NULL,                       /* print */
    ( getattrfunc ) crypto_X509_getattr,
};

/*
 * Initialize the X509 part of the crypto sub module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509( PyObject * dict )
{
    crypto_X509_Type.ob_type = &PyType_Type;
    Py_INCREF( &crypto_X509_Type );
    PyDict_SetItemString( dict, "X509Type",
                          ( PyObject * ) & crypto_X509_Type );
    return 1;
}
