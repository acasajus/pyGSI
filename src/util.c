#include <Python.h>
#include <datetime.h>
#include <openssl/asn1.h>
#include "util.h"

void realLogMsg( const char *fileName, int line, int level, char *fmt, ... )
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
PyObject * error_queue_to_list( void )
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
void flush_error_queue( void )
{
  while( ERR_get_error() != 0 ) {};
  /*
     PyObject *errlist;
     errlist = error_queue_to_list();
     Py_DECREF( errlist );
     */
}

void initialize_python_datetime( void )
{
  PyDateTime_IMPORT;
}

unsigned short convertASN1_TIMETotm( ASN1_TIME * asn1Time, struct tm *time_tm ) {
  return convertStringTotm( ASN1_STRING_data( asn1Time ), time_tm );
}

unsigned short convertStringTotm( unsigned char* asn1String, struct tm *time_tm )
{
  int len;
  char zone;


  len = (int)strlen( ( char * ) asn1String );
  /* dont understand */
  if ( ( len != 13 ) && ( len != 15 ) )
  {
    return 0;
  }

  if ( len == 13 )
  {
    len = sscanf( ( char * ) asn1String, "%02d%02d%02d%02d%02d%02d%c",
        &( time_tm->tm_year ),
        &( time_tm->tm_mon ),
        &( time_tm->tm_mday ),
        &( time_tm->tm_hour ),
        &( time_tm->tm_min ), &( time_tm->tm_sec ), &zone );
    //HACK: We don't expect this code to run past 2100s or receive certs pre-2000
    time_tm->tm_year += 2000;
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) )
    {
      return 0;
    }
  }

  if ( len == 15 )
  {
    len = sscanf( ( char * ) asn1String, "%04d%02d%02d%02d%02d%02d%c",
        &( time_tm->tm_year ),
        &( time_tm->tm_mon ),
        &( time_tm->tm_mday ),
        &( time_tm->tm_hour ),
        &( time_tm->tm_min ), &( time_tm->tm_sec ), &zone );
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) )
    {
      return 0;
    }
  }
#ifdef _BSD_SOURCE
  time_tm->tm_zone = &zone;
#endif

  return 1;
}

PyObject* convertStringToDateTime( unsigned char* asn1String ) {
  PyObject *datetime;
  struct tm time_tm;

  if ( !convertStringTotm( asn1String, &time_tm ) )
  {
    Py_RETURN_NONE;
  }

  datetime = PyDateTime_FromDateAndTime( time_tm.tm_year,
      time_tm.tm_mon,
      time_tm.tm_mday,
      time_tm.tm_hour,
      time_tm.tm_min,
      time_tm.tm_sec, 0 );
  /* dont understand */
  if ( !datetime )
  {
    Py_RETURN_NONE;
  }
  return datetime;

}

PyObject* convertASN1_TIMEToDateTime( ASN1_TIME * asn1Time )
{
  PyObject *datetime;
  struct tm time_tm;

  if ( !convertASN1_TIMETotm( asn1Time, &time_tm ) )
  {
    Py_RETURN_NONE;
  }

  datetime = PyDateTime_FromDateAndTime( time_tm.tm_year,
      time_tm.tm_mon,
      time_tm.tm_mday,
      time_tm.tm_hour,
      time_tm.tm_min,
      time_tm.tm_sec, 0 );
  /* dont understand */
  if ( !datetime )
  {
    Py_RETURN_NONE;
  }
  return datetime;
}

PyObject* astringToDatetime(char*buf, long len) {
  PyObject *datetime;
  struct tm time_tm;
  char zone;

  if ( ( len != 13 ) && ( len != 15 ) ) {
      Py_RETURN_NONE;
  }

  if ( len == 13 ) {
    len = sscanf( (const char*)buf, "%02d%02d%02d%02d%02d%02d%c", &( time_tm.tm_year ), &( time_tm.tm_mon ), 
                       &( time_tm.tm_mday ), &( time_tm.tm_hour ), &( time_tm.tm_min ), &( time_tm.tm_sec ), &zone );
    //HACK: We don't expect this code to run past 2100s or receive certs pre-2000
    time_tm.tm_year += 2000;
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) ) {
      Py_RETURN_NONE;
    }
  }

  if ( len == 15 ) {
    len = sscanf( (const char*)buf, "20%02d%02d%02d%02d%02d%02d%c", &( time_tm.tm_year ), &( time_tm.tm_mon ), &( time_tm.tm_mday ),
                       &( time_tm.tm_hour ), &( time_tm.tm_min ), &( time_tm.tm_sec ), &zone );
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) ) {
      Py_RETURN_NONE;
    }
  }
#ifdef _BSD_SOURCE
  time_tm.tm_zone = &zone;
#endif
  printf("DATE IS %d-%d-%d %d:%d:%d\n", time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
                                         time_tm.tm_min, time_tm.tm_sec );

  datetime = PyDateTime_FromDateAndTime( time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
                                         time_tm.tm_min, time_tm.tm_sec, 0 );

  printf("DATE IS %d-%d-%d %d:%d:%d\n", time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
                                         time_tm.tm_min, time_tm.tm_sec );
  /* dont understand */
  if ( !datetime ) {
    Py_RETURN_NONE;
  }
  return datetime;

}


