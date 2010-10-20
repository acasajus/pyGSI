
/*
 * util.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * Utility functions.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>
#include "util.h"

static char *CVSid =
    "@(#) $Id: util.c,v 1.3 2008/07/08 10:54:55 acasajus Exp $";


static void
realLogMsg( const char *fileName, int line, int level, char *fmt, ... )
{
	char *mesg;
	va_list ap;

	if ( level < GSI_DBG_LOGLVL )
		return;

	va_start( ap, fmt );
	if( vasprintf( &mesg, fmt, ap ) == -1 ) return;
	va_end( ap );

        printf( "[%s -> %d][%d] %s\n", fileName, line, level, mesg );

	free( mesg );
}

/*
 * Flush OpenSSL's error queue and return a list of errors (a (library,
 * function, reason) string tuple)
 *
 * Arguments: None
 * Returns:   A list of errors (new reference)
 */
PyObject *
error_queue_to_list( void )
{
    PyObject *errlist, *tuple;
    long err;

    errlist = PyList_New( 0 );

    while ( ( err = ERR_get_error(  ) ) != 0 )
    {
        tuple = Py_BuildValue( "(sss)", ERR_lib_error_string( err ),
                               ERR_func_error_string( err ),
                               ERR_reason_error_string( err ) );
        PyList_Append( errlist, tuple );
        Py_DECREF( tuple );
    }

    return errlist;
}

/*
 * Flush OpenSSL's error queue and ignore the result
 *
 * Arguments: None
 * Returns:   None
 */
void
flush_error_queue( void )
{
    Py_DECREF( error_queue_to_list() );
}
