
#ifndef PyGSI_UTIL_H_
#define PyGSI_UTIL_H_

#include <Python.h>
#include <time.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>


/*
 * pymemcompat written by Michael Hudson and lets you program to the
 * Python 2.3 memory API while keeping backwards compatability.
 */
#include "pymemcompat.h"

extern PyObject *error_queue_to_list( void );
extern void flush_error_queue( void );
extern void realLogMsg( const char *fileName, int line, int level, char *fmt, ... );


#define OBJ_BEGIN_THREADS( obj ) if( !obj -> tstate ) obj->tstate = PyEval_SaveThread()
#define OBJ_END_THREADS( obj ) if ( obj-> tstate ) { PyEval_RestoreThread( obj-> tstate ); obj->tstate = NULL;  }

#ifndef GSI_DBG_LOGLVL
#define GSI_DBG_LOGLVL 10
#endif

#define logMsg(...) realLogMsg(__FILE__, __LINE__, __VA_ARGS__) 

extern void initialize_python_datetime( void );
unsigned short convertASN1_TIMETotm( ASN1_TIME * asn1Time, struct tm *time_tm );
PyObject * convertASN1_TIMEToDateTime( ASN1_TIME * asn1Time );
unsigned short convertStringTotm( unsigned char * asn1String, struct tm *time_tm );
PyObject * convertStringToDateTime( unsigned char * asn1String );
PyObject* astringToDatetime(char*buf, long len) ;

#if !defined(PY_MAJOR_VERSION) || PY_VERSION_HEX < 0x02000000
static int
PyModule_AddObject( PyObject * m, char *name, PyObject * o )
{
    PyObject *dict;

    if ( !PyModule_Check( m ) || o == NULL )
        return -1;
    dict = PyModule_GetDict( m );
    if ( dict == NULL )
        return -1;
    if ( PyDict_SetItemString( dict, name, o ) )
        return -1;
    Py_DECREF( o );
    return 0;
}

static int
PyModule_AddIntConstant( PyObject * m, char *name, long value )
{
    return PyModule_AddObject( m, name, PyInt_FromLong( value ) );
}

static int
PyObject_AsFileDescriptor( PyObject * o )
{
    int fd;
    PyObject *meth;

    if ( PyInt_Check( o ) )
    {
        fd = PyInt_AsLong( o );
    }
    else if ( PyLong_Check( o ) )
    {
        fd = PyLong_AsLong( o );
    }
    else if ( ( meth = PyObject_GetAttrString( o, "fileno" ) ) != NULL )
    {
        PyObject *fno = PyEval_CallObject( meth, NULL );

        Py_DECREF( meth );
        if ( fno == NULL )
            return -1;

        if ( PyInt_Check( fno ) )
        {
            fd = PyInt_AsLong( fno );
            Py_DECREF( fno );
        }
        else if ( PyLong_Check( fno ) )
        {
            fd = PyLong_AsLong( fno );
            Py_DECREF( fno );
        }
        else
        {
            PyErr_SetString( PyExc_TypeError,
                             "fileno() returned a non-integer" );
            Py_DECREF( fno );
            return -1;
        }
    }
    else
    {
        PyErr_SetString( PyExc_TypeError,
                         "argument must be an int, or have a fileno() method." );
        return -1;
    }

    if ( fd < 0 )
    {
        PyErr_Format( PyExc_ValueError,
                      "file descriptor cannot be a negative integer (%i)",
                      fd );
        return -1;
    }
    return fd;
}
#endif

#endif
