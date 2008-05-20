/*
 * x509name.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * X.509 Name handling, mostly thin wrapping.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

static char *CVSid = "@(#) $Id: x509name.c,v 1.5 2008/05/20 16:48:44 acasajus Exp $";


static char crypto_X509Name_one_line_doc[] = "\n\
Return X509 subject in one line.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   String containing the value\n\
";

static PyObject *
crypto_X509Name_one_line(crypto_X509NameObj *self, PyObject *args)
{
   char *subject;
   PyObject *pyString;

   if (!PyArg_ParseTuple(args, ":subject_name_hash"))
      return NULL;

   subject = X509_NAME_oneline( self->x509_name, NULL, 0 );
   if( !subject ) return NULL;

   pyString = PyString_FromString( subject );
   OPENSSL_free(subject);
   return pyString;
}

static char crypto_X509Name_hash_doc[] = "\n\
Return the has value of this name\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   None\n\
";

/*
 * First four bytes of the MD5 digest of the DER form of an X509Name.
 *
 * Arguments: self - The X509Name object
 * Returns:   An integer giving the hash.
 */
static PyObject *
crypto_X509Name_hash(crypto_X509NameObj *self, PyObject* args)
{
    unsigned long hash;

    if (!PyArg_ParseTuple(args, ":hash")) {
        return NULL;
    }
    hash = X509_NAME_hash(self->x509_name);
    return PyInt_FromLong(hash);
}

static char crypto_X509Name_der_doc[] = "\n\
Return the DER encodeing of this name\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   None\n\
";

/*
 * Arguments: self - The X509Name object
 * Returns:   The DER form of an X509Name.
 */
static PyObject *
crypto_X509Name_der(crypto_X509NameObj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":der")) {
        return NULL;
    }

    i2d_X509_NAME(self->x509_name, 0);
    return PyString_FromStringAndSize(self->x509_name->bytes->data,
                                      self->x509_name->bytes->length);
}

static char crypto_X509Name_get_components_doc[] = "\n\
Returns the split-up components of this name.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   List of tuples (name, value).\n\
";

static PyObject *
crypto_X509Name_get_components(crypto_X509NameObj *self, PyObject *args)
{
    int n, i;
    X509_NAME *name = self->x509_name;
    PyObject *list;

    if (!PyArg_ParseTuple(args, ":get_components"))
        return NULL;

    n = X509_NAME_entry_count(name);
    list = PyList_New(n);
    for (i = 0; i < n; i++)
    {
        X509_NAME_ENTRY *ent;
        ASN1_OBJECT *fname;
        ASN1_STRING *fval;
        int nid;
        int l;
        unsigned char buf[100];
        unsigned char *str;
        PyObject *tuple;

        ent = X509_NAME_get_entry(name, i);

        fname = X509_NAME_ENTRY_get_object(ent);
        fval = X509_NAME_ENTRY_get_data(ent);

        l = ASN1_STRING_length(fval);
        str = ASN1_STRING_data(fval);

        nid = OBJ_obj2nid(fname);

        /* printf("fname is %s len=%d str=%s\n", OBJ_nid2sn(nid), l, str); */

        tuple = PyTuple_New(2);
        PyTuple_SetItem(tuple, 0, PyString_FromString(OBJ_nid2sn(nid)));
        PyTuple_SetItem(tuple, 1, PyString_FromStringAndSize(str, l));

        PyList_SetItem(list, i, tuple);
    }

    return list;
}


/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_X509Name_##name, METH_VARARGS, crypto_X509Name_##name##_doc }
static PyMethodDef crypto_X509Name_methods[] =
{
    ADD_METHOD(one_line),
    ADD_METHOD(hash),
    ADD_METHOD(der),
    ADD_METHOD(get_components),
    { NULL, NULL }
};
#undef ADD_METHOD

/*
 * Constructor for X509Name, never called by Python code directly
 *
 * Arguments: name    - A "real" X509_NAME object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" X509_NAME object
 * Returns:   The newly created X509Name object
 */
crypto_X509NameObj *
crypto_X509Name_New(X509_NAME *name, int dealloc)
{
    crypto_X509NameObj *self;

    self = PyObject_GC_New(crypto_X509NameObj, &crypto_X509Name_Type);

    if (self == NULL)
        return NULL;

    self->x509_name = name;
    self->dealloc = dealloc;
    self->parent_cert = NULL;

    PyObject_GC_Track(self);
    return self;
}

/*
 * Return a name string given a X509_NAME object and a name identifier. Used
 * by the getattr function.
 *
 * Arguments: name - The X509_NAME object
 *            nid  - The name identifier
 * Returns:   The name as a Python string object
 */
static int
get_name_by_nid(X509_NAME *name, int nid, char **utf8string)
{
    int entry_idx;
    X509_NAME_ENTRY *entry;
    ASN1_STRING *data;
    int len;

    if ((entry_idx = X509_NAME_get_index_by_NID(name, nid, -1)) == -1)
    {
        return 0;
    }
    entry = X509_NAME_get_entry(name, entry_idx);
    data = X509_NAME_ENTRY_get_data(entry);
    if ((len = ASN1_STRING_to_UTF8((unsigned char **)utf8string, data)) < 0)
    {
        exception_from_error_queue();
        return -1;
    }

    return len;
}

/*
 * Given a X509_NAME object and a name identifier, set the corresponding
 * attribute to the given string. Used by the setattr function.
 *
 * Arguments: name  - The X509_NAME object
 *            nid   - The name identifier
 *            nidIndex - Index of the nid in case there are more than one
 *            value - The string to set
 * Returns:   0 for success, -1 on failure
 */
static int
set_name_by_nid(X509_NAME *name, int nid, int nidIndex, char *utf8string)
{
    X509_NAME_ENTRY *ne;
    int i, entry_count, temp_nid;

    /* If there's an old entry for this NID, remove it */
    /*
    entry_count = X509_NAME_entry_count(name);
    for (i = 0; i < entry_count; i++)
    {
        ne = X509_NAME_get_entry(name, i);
        temp_nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne));
        if (temp_nid == nid)
        {
            ne = X509_NAME_delete_entry(name, i);
            X509_NAME_ENTRY_free(ne);
            break;
        }
    }
    */

    /* Add the new entry */
    if (!X509_NAME_add_entry_by_NID(name, nid, MBSTRING_UTF8, utf8string,
                -1, nidIndex, 0))
    {
        exception_from_error_queue();
        return -1;
    }
    return 0;
}


/*
 * Find attribute. An X509Name object has the following attributes:
 * countryName (alias C), stateOrProvince (alias ST), locality (alias L),
 * organization (alias O), organizationalUnit (alias OU), commonName (alias
 * CN) and more...
 *
 * Arguments: self - The X509Name object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
crypto_X509Name_getattr(crypto_X509NameObj *self, char *name)
{
    int nid, len;
    char *utf8string;
    PyObject *meth;

   meth = Py_FindMethod(crypto_X509Name_methods, (PyObject *)self, name );
   if ( PyErr_Occurred() && PyErr_ExceptionMatches( PyExc_AttributeError ) )
      PyErr_Clear();
   else
      return meth;

   if ((nid = OBJ_txt2nid(name)) == NID_undef)
   {
      PyErr_SetString(PyExc_AttributeError, "No such attribute");
      return NULL;
   }

   len = get_name_by_nid(self->x509_name, nid, &utf8string);
   if (len < 0)
      return NULL;
   else if (len == 0)
   {
      Py_INCREF(Py_None);
      return Py_None;
   }
   else
   {
	  PyObject* meth = PyUnicode_Decode(utf8string, len, "utf-8", NULL);
	  OPENSSL_free(utf8string);
	  return meth;
   }
}

/*
 * Set attribute
 *
 * Arguments: self  - The X509Name object
 *            name  - The attribute name
 *            value - The value to set
 */
static int
crypto_X509Name_setattr(crypto_X509NameObj *self, char *name, PyObject *value)
{
    int nid,result,nidIndex;
    char *buffer, *divP;

    divP = strchr( name, '.' );
    if( !divP )
    	nidIndex = -1;
    else
    {
    	*divP = 0;
    	nidIndex = atoi( divP+1 );
    }

    if ((nid = OBJ_txt2nid(name)) == NID_undef)
    {
        PyErr_SetString(PyExc_AttributeError, "No such attribute");
        return -1;
    }

    /* Something of a hack to get nice unicode behaviour */
    if (!PyArg_Parse(value, "es:setattr", "utf-8", &buffer))
        return -1;

    result = set_name_by_nid(self->x509_name, nid, nidIndex, buffer);
    PyMem_Free(buffer);
    return result;
}

/*
 * Compare two X509Name structures.
 *
 * Arguments: n - The first X509Name
 *            m - The second X509Name
 * Returns:   <0 if n < m, 0 if n == m and >0 if n > m
 */
static int
crypto_X509Name_compare(crypto_X509NameObj *n, crypto_X509NameObj *m)
{
    return X509_NAME_cmp(n->x509_name, m->x509_name);
}

/*
 * String representation of an X509Name
 *
 * Arguments: self - The X509Name object
 * Returns:   A string representation of the object
 */
static PyObject *
crypto_X509Name_repr(crypto_X509NameObj *self)
{
    char tmpbuf[512] = "";
    char realbuf[512+64];

    if (X509_NAME_oneline(self->x509_name, tmpbuf, 512) == NULL)
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        /* This is safe because tmpbuf is max 512 characters */
        sprintf(realbuf, "<X509Name object '%s'>", tmpbuf);
        return PyString_FromString(realbuf);
    }
}

/*
 * Call the visitproc on all contained objects.
 *
 * Arguments: self - The Connection object
 *            visit - Function to call
 *            arg - Extra argument to visit
 * Returns:   0 if all goes well, otherwise the return code from the first
 *            call that gave non-zero result.
 */
static int
crypto_X509Name_traverse(crypto_X509NameObj *self, visitproc visit, void *arg)
{
    Py_VISIT( self->parent_cert );
    return 0;
}

/*
 * Decref all contained objects and zero the pointers.
 *
 * Arguments: self - The Connection object
 * Returns:   Always 0.
 */
static int
crypto_X509Name_clear(crypto_X509NameObj *self)
{
    Py_CLEAR( self->parent_cert );
    return 0;
}

/*
 * Deallocate the memory used by the X509Name object
 *
 * Arguments: self - The X509Name object
 * Returns:   None
 */
static void
crypto_X509Name_dealloc(crypto_X509NameObj *self)
{
    PyObject_GC_UnTrack(self);

    crypto_X509Name_clear(self);
    /* Sometimes we don't have to dealloc this */
    if (self->dealloc)
        X509_NAME_free(self->x509_name);

    PyObject_GC_Del(self);
}

PyTypeObject crypto_X509Name_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "X509Name",
    sizeof(crypto_X509NameObj),
    0,
    (destructor)crypto_X509Name_dealloc,
    NULL, /* print */
    (getattrfunc)crypto_X509Name_getattr,
    (setattrfunc)crypto_X509Name_setattr,
    (cmpfunc)crypto_X509Name_compare,
    (reprfunc)crypto_X509Name_repr,
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
    NULL, /* call */
    NULL, /* str */
    NULL, /* getattro */
    NULL, /* setattro */
    NULL, /* as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    NULL, /* doc */
    (traverseproc)crypto_X509Name_traverse,
    (inquiry)crypto_X509Name_clear,
};


/*
 * Initialize the X509Name part of the crypto module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509name(PyObject *dict)
{
    crypto_X509Name_Type.ob_type = &PyType_Type;
    Py_INCREF(&crypto_X509Name_Type);
    PyDict_SetItemString(dict, "X509NameType", (PyObject *)&crypto_X509Name_Type);
    return 1;
}
