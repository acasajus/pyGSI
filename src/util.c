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

static char *CVSid = "@(#) $Id: util.c,v 1.1 2008/02/29 18:46:03 acasajus Exp $";


/*
 * Flush OpenSSL's error queue and return a list of errors (a (library,
 * function, reason) string tuple)
 *
 * Arguments: None
 * Returns:   A list of errors (new reference)
 */
PyObject *
error_queue_to_list(void)
{
    PyObject *errlist, *tuple;
    long err;

    errlist = PyList_New(0);

    while ((err = ERR_get_error()) != 0)
    {
	tuple = Py_BuildValue("(sss)", ERR_lib_error_string(err),
		                       ERR_func_error_string(err),
				       ERR_reason_error_string(err));
        PyList_Append(errlist, tuple);
        Py_DECREF(tuple);
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
flush_error_queue(void)
{
    Py_DECREF(error_queue_to_list());
}

/// ASN1 time string (in a char *) to time_t
/**
 *  (Use ASN1_STRING_data() to convert ASN1_GENERALIZEDTIME to char * if
 *   necessary)
 */

time_t GRSTasn1TimeToTimeT(char *asn1time, size_t len)
{
   char   zone;
   struct tm time_tm;

   if (len == 0) len = strlen(asn1time);

   if ((len != 13) && (len != 15)) return 0; /* dont understand */

   if ((len == 13) &&
       ((sscanf(asn1time, "%02d%02d%02d%02d%02d%02d%c",
         &(time_tm.tm_year),
         &(time_tm.tm_mon),
         &(time_tm.tm_mday),
         &(time_tm.tm_hour),
         &(time_tm.tm_min),
         &(time_tm.tm_sec),
         &zone) != 7) || (zone != 'Z'))) return 0; /* dont understand */

   if ((len == 15) &&
       ((sscanf(asn1time, "20%02d%02d%02d%02d%02d%02d%c",
         &(time_tm.tm_year),
         &(time_tm.tm_mon),
         &(time_tm.tm_mday),
         &(time_tm.tm_hour),
         &(time_tm.tm_min),
         &(time_tm.tm_sec),
         &zone) != 7) || (zone != 'Z'))) return 0; /* dont understand */

   /* time format fixups */

   if (time_tm.tm_year < 90) time_tm.tm_year += 100;
   --(time_tm.tm_mon);

   return timegm(&time_tm);
}
