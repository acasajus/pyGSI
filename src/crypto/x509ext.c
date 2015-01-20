
#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

static char crypto_X509Extension_get_critical_doc[] = "\n\
Returns the critical field of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: The critical field.\n\
";

static PyObject *
crypto_X509Extension_get_critical( crypto_X509ExtensionObj * self,
                                   PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_critical" ) )
        return NULL;

    return
        PyInt_FromLong( X509_EXTENSION_get_critical( self->x509_extension ) );
}

static char crypto_X509Extension_set_critical_doc[] = "\n\
Sets critical field of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: None.\n\
";

static PyObject *
crypto_X509Extension_set_critical( crypto_X509ExtensionObj * self,
                                   PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":set_critical" ) )
        return NULL;

    X509_EXTENSION_set_critical( self->x509_extension, 1 ) ;
    Py_RETURN_NONE;
}

static char crypto_X509Extension_set_no_critical_doc[] = "\n\
Sets critical field to false of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: None.\n\
";

static PyObject *
crypto_X509Extension_set_no_critical( crypto_X509ExtensionObj * self,
                                   PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":set_no_critical" ) )
        return NULL;

    X509_EXTENSION_set_critical( self->x509_extension, 0 ) ;
    Py_RETURN_NONE;
}


static char crypto_X509Extension_get_value_doc[] = "\n\
Returns the value of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: The value.\n\
";

static PyObject *
crypto_X509Extension_get_value( crypto_X509ExtensionObj * self,
                                PyObject * args )
{
    long str_len;
    char *tmp_str;
    PyObject *str;
    BIO *bio = BIO_new( BIO_s_mem(  ) );

    if ( !PyArg_ParseTuple( args, ":get_value" ) )
        return NULL;

    if ( !X509V3_EXT_print( bio, self->x509_extension, 0, 0 ) )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }
    str_len = BIO_get_mem_data( bio, &tmp_str );
    str = PyString_FromStringAndSize( tmp_str, str_len );

    BIO_free( bio );

    return str;
}

static char crypto_X509Extension_get_asn1_value_doc[] = "\n\
Returns the raw (binary) value of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: The value.\n\
";

static PyObject *
crypto_X509Extension_get_asn1_value( crypto_X509ExtensionObj * self,
                                PyObject * args )
{
    long done;
    if ( !PyArg_ParseTuple( args, ":get_asn1_value" ) )
        return NULL;

    return (PyObject*)loads_asn1((char*)self->x509_extension->value->data,self->x509_extension->value->length,&done);
}

static char crypto_X509Extension_get_raw_value_doc[] = "\n\
Returns the raw (binary) value of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: The value.\n\
";

static PyObject *
crypto_X509Extension_get_raw_value( crypto_X509ExtensionObj * self,
                                PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_raw_value" ) )
        return NULL;

    return PyByteArray_FromStringAndSize((const char*)self->x509_extension->value->data,self->x509_extension->value->length);
}

static char crypto_X509Extension_get_nid_doc[] = "\n\
Returns the nid of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: Extension nid\n\
";

static PyObject *
crypto_X509Extension_get_nid( crypto_X509ExtensionObj * self,
                              PyObject * args )
{
    ASN1_OBJECT *obj;

    if ( !PyArg_ParseTuple( args, ":get_nid" ) )
        return NULL;

    obj = X509_EXTENSION_get_object( self->x509_extension );
    if ( !obj )
    {
        exception_from_error_queue(  );
        return NULL;
    }

    return PyInt_FromLong( OBJ_obj2nid( obj ) );
}

static char crypto_X509Extension_get_sn_doc[] = "\n\
Returns the short name of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: Extension short name\n\
";

static PyObject *
crypto_X509Extension_get_sn( crypto_X509ExtensionObj * self, PyObject * args )
{
    ASN1_OBJECT *obj;
    const char *sn;

    if ( !PyArg_ParseTuple( args, ":get_sn" ) )
        return NULL;

    obj = X509_EXTENSION_get_object( self->x509_extension );
    if ( !obj )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    sn = OBJ_nid2sn( OBJ_obj2nid( obj ) );
    if ( !sn )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    return PyString_FromString( sn );
}

static char crypto_X509Extension_get_ln_doc[] = "\n\
Returns the short name of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: Extension short name\n\
";

static PyObject *
crypto_X509Extension_get_ln( crypto_X509ExtensionObj * self, PyObject * args )
{
    ASN1_OBJECT *obj;
    const char *ln;

    if ( !PyArg_ParseTuple( args, ":get_ln" ) )
        return NULL;

    obj = X509_EXTENSION_get_object( self->x509_extension );
    if ( !obj )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    ln = OBJ_nid2ln( OBJ_obj2nid( obj ) );
    if ( !ln )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    return PyString_FromString( ln );
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509Extension_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
{ #name, (PyCFunction)crypto_X509Extension_##name, METH_VARARGS, crypto_X509Extension_##name##_doc }
static PyMethodDef crypto_X509Extension_methods[] = {
    ADD_METHOD( get_critical ),
    ADD_METHOD( set_critical ),
    ADD_METHOD( set_no_critical ),
    ADD_METHOD( get_value ),
    ADD_METHOD( get_asn1_value ),
    ADD_METHOD( get_raw_value ),
    ADD_METHOD( get_nid ),
    ADD_METHOD( get_sn ),
    ADD_METHOD( get_ln ),
    {NULL, NULL}
};

#undef ADD_METHOD

/*
 * Constructor for X509Extension, never called by Python code directly
 *
 * Arguments: type_name - ???
 *            critical  - ???
 *            value     - ???
 * Returns:   The newly created X509Extension object
 */
crypto_X509ExtensionObj *
crypto_X509Extension_New( char *type_name, char *value, int val_length )
{
    crypto_X509ExtensionObj *self;
    int ext_nid;
    X509_EXTENSION *extension = NULL;

    /* Try to get a NID for the name */
    if ( ( ext_nid = OBJ_sn2nid( type_name ) ) == NID_undef )
    {
        PyErr_SetString( PyExc_ValueError, "Unknown extension name" );
        return NULL;
    }
    extension = X509V3_EXT_conf_nid( NULL, NULL, ext_nid, value );
    if ( !extension )
    {
        //PyErr_SetString(PyExc_ValueError, "Can't create extension");
        exception_from_error_queue(  );
        return NULL;
    }

    self = PyObject_New( crypto_X509ExtensionObj, &crypto_X509Extension_Type );
    if ( self == NULL )
    {
        X509_EXTENSION_free( extension );
        return NULL;
    }

    self->x509_extension = extension;
    self->dealloc = 1;

    return self;
}

/*
 * Deallocate the memory used by the X509Extension object
 *
 * Arguments: self - The X509Extension object
 * Returns:   None
 */
static void
crypto_X509Extension_dealloc( crypto_X509ExtensionObj * self )
{
    /* Sometimes we don't have to dealloc this */
    if ( self->dealloc )
        X509_EXTENSION_free( self->x509_extension );

    PyObject_Del( self );
}

/*
 * Find attribute
 *
 * Arguments: self - The X509Extension object
 *            name - The attribute name
 * Returns: A Python object for the attribute, or NULL if something
 *          went wrong.
 */
static PyObject *
crypto_X509Extension_getattr( crypto_X509ExtensionObj * self, char *name )
{
    return Py_FindMethod( crypto_X509Extension_methods, ( PyObject * ) self,
                          name );
}

/*
 * Print a nice text representation of the certificate request.
 */
static PyObject *
crypto_X509Extension_value_str( crypto_X509ExtensionObj * self )
{
    long str_len;
    char *tmp_str;
    PyObject *str;
    BIO *bio = BIO_new( BIO_s_mem(  ) );

    if ( !X509V3_EXT_print( bio, self->x509_extension, 0, 0 ) )
    {
        BIO_free( bio );
        exception_from_error_queue(  );
        return NULL;
    }
    str_len = BIO_get_mem_data( bio, &tmp_str );
    str = PyString_FromStringAndSize( tmp_str, str_len );

    BIO_free( bio );

    return str;
}

PyTypeObject crypto_X509Extension_Type = {
    PyObject_HEAD_INIT( NULL ) 0,
    "X509Extension",
    sizeof( crypto_X509ExtensionObj ),
    0,
    ( destructor ) crypto_X509Extension_dealloc,
    NULL,                       /* print */
    ( getattrfunc ) crypto_X509Extension_getattr,
    NULL,                       /* setattr  (setattrfunc)crypto_X509Name_setattr, */
    NULL,                       /* compare */
    NULL,                       /* repr */
    NULL,                       /* as_number */
    NULL,                       /* as_sequence */
    NULL,                       /* as_mapping */
    NULL,                       /* hash */
    NULL,                       /* call */
    ( reprfunc ) crypto_X509Extension_value_str /* str */
};

/*
 * Initialize the X509Extension part of the crypto module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509extension( PyObject * dict )
{
    crypto_X509Extension_Type.ob_type = &PyType_Type;
    Py_INCREF( &crypto_X509Extension_Type );
    PyDict_SetItemString( dict, "X509ExtensionType",
                          ( PyObject * ) & crypto_X509Extension_Type );
    return 1;
}
