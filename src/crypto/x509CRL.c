#include <Python.h>
#define crypto_MODULE
#include "crypto.h"


static char crypto_X509CRL_get_issuer_doc[] = "\n\
Returns the issuer of the CRL.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   X509 issuer name of the CRL\n\
";

static PyObject *
crypto_X509CRL_get_issuer( crypto_X509CRLObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_issuer" ) )
        return NULL;

    return (PyObject*) crypto_X509Name_New( X509_CRL_get_issuer( self->crl ), 0 );
}


static char crypto_X509CRL_has_expired_doc[] = "\n\
Returns in the CRL has expired.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if the CRL has expired\n\
";

static PyObject *
crypto_X509CRL_has_expired( crypto_X509CRLObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":has_expired" ) )
        return NULL;

    if ( ASN1_UTCTIME_cmp_time_t( X509_CRL_get_nextUpdate( self->crl ), time( NULL ) ) <
         0 )
    	Py_RETURN_TRUE;
    else
    	Py_RETURN_FALSE;
}

static char crypto_X509CRL_get_next_update_doc[] = "\n\
Get the next update datetime for the CRL.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Next update datetime\n\
";

static PyObject *
crypto_X509CRL_get_next_update( crypto_X509CRLObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_next_update" ) )
        return NULL;

    return convertASN1_TIMEToDateTime( X509_CRL_get_nextUpdate( self->crl ) );
}

static char crypto_X509CRL_get_last_update_doc[] = "\n\
Get the last update datetime for the CRL.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Last update datetime\n\
";

static PyObject *
crypto_X509CRL_get_last_update( crypto_X509CRLObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_last_update" ) )
        return NULL;

    return convertASN1_TIMEToDateTime( X509_CRL_get_lastUpdate( self->crl ) );
}


/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_X509CRL_##name, METH_VARARGS, crypto_X509CRL_##name##_doc }
static PyMethodDef crypto_X509CRL_methods[] = {
    ADD_METHOD( get_issuer ),
    ADD_METHOD( has_expired ),
    ADD_METHOD( get_next_update ),
    ADD_METHOD( get_last_update ),
    {NULL, NULL}
};

#undef ADD_METHOD

/*
 * Constructor for X509CRL, never called by Python code directly
 *
 * Arguments: name    - A "real" X509_NAME object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" X509_NAME object
 * Returns:   The newly created X509CRL object
 */
crypto_X509CRLObj *
crypto_X509CRL_New( X509_CRL * crl, int dealloc )
{
    crypto_X509CRLObj *self;

    self = PyObject_New( crypto_X509CRLObj, &crypto_X509CRL_Type );

    if ( self == NULL )
        return NULL;

    self->crl = crl;
    self->dealloc = dealloc;

    return self;
}

/*
 * Compare two X509CRL structures.
 *
 * Arguments: n - The first X509CRL
 *            m - The second X509CRL
 * Returns:   <0 if n < m, 0 if n == m and >0 if n > m
 */
static int
crypto_X509CRL_compare( crypto_X509CRLObj * n, crypto_X509CRLObj * m )
{
    return X509_CRL_cmp( n->crl, m->crl );
}

/*
 * String representation of an X509CRL
 *
 * Arguments: self - The X509CRL object
 * Returns:   A string representation of the object
 */
static PyObject *
crypto_X509CRL_repr( crypto_X509CRLObj * self )
{
    char tmpbuf[512] = "";
    char realbuf[512 + 64];

    if ( X509_NAME_oneline( X509_CRL_get_issuer( self->crl ), tmpbuf, 512 ) == NULL )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    else
    {
        /* This is safe because tmpbuf is max 512 characters */
        sprintf( realbuf, "<X509CRL object '%s'>", tmpbuf );
        return PyString_FromString( realbuf );
    }
}

/*
 * Deallocate the memory used by the X509CRL object
 *
 * Arguments: self - The X509CRL object
 * Returns:   None
 */
static void
crypto_X509CRL_dealloc( crypto_X509CRLObj * self )
{

    /* Sometimes we don't have to dealloc this */
    if ( self->dealloc && self->crl)
    {
        X509_CRL_free( self->crl );
        self->crl = NULL;
    }

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
crypto_X509CRL_getattr( crypto_X509CRLObj * self, char *name )
{
    return Py_FindMethod( crypto_X509CRL_methods, ( PyObject * ) self,
                          name );
}

PyTypeObject crypto_X509CRL_Type = {
    PyObject_HEAD_INIT( NULL ) 0,
    "X509CRL",
    sizeof( crypto_X509CRLObj ),
    0,
    ( destructor ) crypto_X509CRL_dealloc,
    NULL,                       /* print */
    ( getattrfunc ) crypto_X509CRL_getattr,
    NULL,                       /* setattr */
    ( cmpfunc ) crypto_X509CRL_compare,
    ( reprfunc ) crypto_X509CRL_repr,

};


/*
 * Initialize the X509CRL part of the crypto module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509CRL( PyObject * dict )
{
    crypto_X509CRL_Type.ob_type = &PyType_Type;
    Py_INCREF( &crypto_X509CRL_Type );
    PyDict_SetItemString( dict, "X509CRLType",
                          ( PyObject * ) & crypto_X509CRL_Type );
    return 1;
}
