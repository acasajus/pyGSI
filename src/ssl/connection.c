
#include <Python.h>
#define SSL_MODULE
#include <openssl/err.h>
#include "ssl.h"

#ifndef MS_WINDOWS
#  include <sys/socket.h>
#  include <netinet/in.h>
#  if !(defined(__BEOS__) || defined(__CYGWIN__))
#    include <netinet/tcp.h>
#  endif
#else
#  include <winsock.h>
#endif

//static int handshaked = 0;

/**
 * If we are on UNIX, fine, just use PyErr_SetFromErrno. If we are on Windows,
 * apply some black winsock voodoo. This is basically just copied from Python's
 * socketmodule.c
 *
 * Arguments: None
 * Returns:   None
 */
static void
syscall_from_errno( void )
{
#ifdef MS_WINDOWS
    int errnum = WSAGetLastError(  );

    if ( errnum )
    {
        static struct
        {
            int num;
            const char *msg;
        } *msgp, msgs[] =
        {
            {
            WSAEINTR, "Interrupted system call"},
            {
            WSAEBADF, "Bad file descriptor"},
            {
            WSAEACCES, "Permission denied"},
            {
            WSAEFAULT, "Bad address"},
            {
            WSAEINVAL, "Invalid argument"},
            {
            WSAEMFILE, "Too many open files"},
            {
            WSAEWOULDBLOCK, "The socket operation could not complete "
                    "without blocking"},
            {
            WSAEINPROGRESS, "Operation now in progress"},
            {
            WSAEALREADY, "Operation already in progress"},
            {
            WSAENOTSOCK, "Socket operation on non-socket"},
            {
            WSAEDESTADDRREQ, "Destination address required"},
            {
            WSAEMSGSIZE, "Message too long"},
            {
            WSAEPROTOTYPE, "Protocol wrong type for socket"},
            {
            WSAENOPROTOOPT, "Protocol not available"},
            {
            WSAEPROTONOSUPPORT, "Protocol not supported"},
            {
            WSAESOCKTNOSUPPORT, "Socket type not supported"},
            {
            WSAEOPNOTSUPP, "Operation not supported"},
            {
            WSAEPFNOSUPPORT, "Protocol family not supported"},
            {
            WSAEAFNOSUPPORT, "Address family not supported"},
            {
            WSAEADDRINUSE, "Address already in use"},
            {
            WSAEADDRNOTAVAIL, "Can't assign requested address"},
            {
            WSAENETDOWN, "Network is down"},
            {
            WSAENETUNREACH, "Network is unreachable"},
            {
            WSAENETRESET, "Network dropped connection on reset"},
            {
            WSAECONNABORTED, "Software caused connection abort"},
            {
            WSAECONNRESET, "Connection reset by peer"},
            {
            WSAENOBUFS, "No buffer space available"},
            {
            WSAEISCONN, "Socket is already connected"},
            {
            WSAENOTCONN, "Socket is not connected"},
            {
            WSAESHUTDOWN, "Can't send after socket shutdown"},
            {
            WSAETOOMANYREFS, "Too many references: can't splice"},
            {
            WSAETIMEDOUT, "Operation timed out"},
            {
            WSAECONNREFUSED, "Connection refused"},
            {
            WSAELOOP, "Too many levels of symbolic links"},
            {
            WSAENAMETOOLONG, "File name too long"},
            {
            WSAEHOSTDOWN, "Host is down"},
            {
            WSAEHOSTUNREACH, "No route to host"},
            {
            WSAENOTEMPTY, "Directory not empty"},
            {
            WSAEPROCLIM, "Too many processes"},
            {
            WSAEUSERS, "Too many users"},
            {
            WSAEDQUOT, "Disc quota exceeded"},
            {
            WSAESTALE, "Stale NFS file handle"},
            {
            WSAEREMOTE, "Too many levels of remote in path"},
            {
            WSASYSNOTREADY, "Network subsystem is unvailable"},
            {
            WSAVERNOTSUPPORTED, "WinSock version is not supported"},
            {
            WSANOTINITIALISED, "Successful WSAStartup() not yet performed"},
            {
            WSAEDISCON, "Graceful shutdown in progress"},
                /* Resolver errors */
            {
            WSAHOST_NOT_FOUND, "No such host is known"},
            {
            WSATRY_AGAIN, "Host not found, or server failed"},
            {
            WSANO_RECOVERY, "Unexpected server error encountered"},
            {
            WSANO_DATA, "Valid name without requested data"},
            {
            WSANO_ADDRESS, "No address, look for MX record"},
            {
            0, NULL}
        };
        PyObject *v;
        const char *msg = "winsock error";

        for ( msgp = msgs; msgp->msg; msgp++ )
        {
            if ( errnum == msgp->num )
            {
                msg = msgp->msg;
                break;
            }
        }

        v = Py_BuildValue( "(is)", errnum, msg );
        if ( v != NULL )
        {
            PyErr_SetObject( ssl_SysCallError, v );
            Py_DECREF( v );
        }
        return;
    }
#else
    PyErr_SetFromErrno( ssl_SysCallError );
#endif
}

/*
 * Handle errors raised by SSL I/O functions. NOTE: Not SSL_shutdown ;)
 *
 * Arguments: ssl - The SSL object
 *            err - The return code from SSL_get_error
 *            ret - The return code from the SSL I/O function
 * Returns:   None, the calling function should return NULL
 */
static void
handle_ssl_errors( SSL * ssl, int err, int ret )
{
    switch ( err )
    {
        /*
         * Strange as it may seem, ZeroReturn is not an error per se. It means
         * that the SSL Connection has been closed correctly (note, not the
         * transport layer!), i.e. closure alerts have been exchanged. This is
         * an exception since
         *  + There's an SSL "error" code for it
         *  + You have to deal with it in any case, close the transport layer
         *    etc
         */
    case SSL_ERROR_ZERO_RETURN:
        PyErr_SetNone( ssl_ZeroReturnError );
        break;

        /*
         * The WantXYZ exceptions don't mean that there's an error, just that
         * nothing could be read/written just now, maybe because the transport
         * layer would block on the operation, or that there's not enough data
         * available to fill an entire SSL record.
         */
    case SSL_ERROR_WANT_READ:
        PyErr_SetNone( ssl_WantReadError );
        break;

    case SSL_ERROR_WANT_WRITE:
        PyErr_SetNone( ssl_WantWriteError );
        break;

    case SSL_ERROR_WANT_X509_LOOKUP:
        PyErr_SetNone( ssl_WantX509LookupError );
        break;

    case SSL_ERROR_SYSCALL:
        if ( ERR_peek_error(  ) == 0 )
        {
            if ( ret < 0 )
            {
                syscall_from_errno(  );
            }
            else
            {
                PyObject *v;

                v = Py_BuildValue( "(is)", -1, "Unexpected EOF" );
                if ( v != NULL )
                {
                    PyErr_SetObject( ssl_SysCallError, v );
                    Py_DECREF( v );
                }
            }
            break;
        }

        /* NOTE: Fall-through here, we don't want to duplicate code,
           right? */

    case SSL_ERROR_SSL:
        ;
    default:
        exception_from_error_queue(  );
        break;
    }
}

/*
 * Here be member methods of the Connection "class"
 */

static char ssl_Connection_get_context_doc[] = "\n\
Get session context\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   A Context object\n\
";
static PyObject *
ssl_Connection_get_context( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_context" ) )
        return NULL;

    Py_INCREF( self->context );
    return ( PyObject * ) self->context;
}

static char ssl_Connection_pending_doc[] = "\n\
Get the number of bytes that can be safely read from the connection\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   \n\
";
static PyObject *
ssl_Connection_pending( ssl_ConnectionObj * self, PyObject * args )
{
    int ret;

    if ( !PyArg_ParseTuple( args, ":pending" ) )
        return NULL;

    ret = SSL_pending( self->ssl );
    return PyInt_FromLong( ( long ) ret );
}

static char ssl_Connection_send_doc[] = "\n\
Send data on the connection. NOTE: If you get one of the WantRead,\n\
WantWrite or WantX509Lookup exceptions on this, you have to call the\n\
method again with the SAME buffer.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
             buf   - The string to send\n\
             flags - (optional) Included for compatability with the socket\n\
                     API, the value is ignored\n\
Returns:   The number of bytes written\n\
";
static PyObject *
ssl_Connection_send( ssl_ConnectionObj * self, PyObject * args )
{
    char *buf;
    int len, ret, err, flags;

    if ( !PyArg_ParseTuple( args, "s#|i:send", &buf, &len, &flags ) )
        return NULL;

    OBJ_BEGIN_THREADS( self );
    ret = SSL_write( self->ssl, buf, len );
    OBJ_END_THREADS( self );

    err = SSL_get_error( self->ssl, ret );
    if ( err != SSL_ERROR_NONE )
    {
    	handle_ssl_errors( self->ssl, err, ret );
    	return NULL;
    }

    return PyInt_FromLong( ( long ) ret );
}

static char ssl_Connection_sendall_doc[] = "\n\
Send \"all\" data on the connection. This calls send() repeatedly until\n\
all data is sent. If an error occurs, it's impossible to tell how much data\n\
has been sent.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
             buf   - The string to send\n\
             flags - (optional) Included for compatability with the socket\n\
                     API, the value is ignored\n\
Returns:   The number of bytes written\n\
";
static PyObject *
ssl_Connection_sendall( ssl_ConnectionObj * self, PyObject * args )
{
    char *buf;
    int len, ret, err, flags;

    if ( !PyArg_ParseTuple( args, "s#|i:sendall", &buf, &len, &flags ) )
        return NULL;

    do
    {
        OBJ_BEGIN_THREADS( self );
        ret = SSL_write( self->ssl, buf, len );
        OBJ_END_THREADS( self );

        err = SSL_get_error( self->ssl, ret );
        if ( err != SSL_ERROR_NONE )
        {
        	handle_ssl_errors( self->ssl, err, ret );
        	return NULL;
        }
		buf += ret;
		len -= ret;
    }
    while ( len > 0 );

    Py_RETURN_NONE;
}

static char ssl_Connection_recv_doc[] = "\n\
Receive data on the connection. NOTE: If you get one of the WantRead,\n\
WantWrite or WantX509Lookup exceptions on this, you have to call the\n\
method again with the SAME buffer.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
             bufsiz - The maximum number of bytes to read\n\
             flags  - (optional) Included for compatability with the socket\n\
                      API, the value is ignored\n\
Returns:   Data read.\n\
";
static PyObject *
ssl_Connection_recv( ssl_ConnectionObj * self, PyObject * args )
{
    int bufsiz, ret, err, flags;
    char *cbuf;
    PyObject *buf;

    if ( !PyArg_ParseTuple( args, "i|i:recv", &bufsiz, &flags ) )
        return NULL;

	if( bufsiz <= 0 )
	{
		//Raise exception
		return NULL;
	}

    cbuf = OPENSSL_malloc( sizeof( char ) * bufsiz );
    if( !cbuf )
    	return NULL;

    OBJ_BEGIN_THREADS( self );
    ret = SSL_read( self->ssl, cbuf, bufsiz );
    OBJ_END_THREADS( self );

    err = SSL_get_error( self->ssl, ret );
    if ( err != SSL_ERROR_NONE )
    {
    	handle_ssl_errors( self->ssl, err, ret );
    	OPENSSL_free( cbuf );
    	return NULL;
    }

    buf = PyString_FromStringAndSize( cbuf, ret );

    OPENSSL_free( cbuf );

    if( !buf )
    	return NULL;

    return buf;
}

    /*

    buf = PyString_FromStringAndSize( NULL, bufsiz );
    if ( buf == NULL )
        return NULL;

    cbuf = PyString_AsString( buf );

    OBJ_BEGIN_THREADS( self );
    ret = SSL_read( self->ssl, cbuf, bufsiz );
    OBJ_END_THREADS( self );

    err = SSL_get_error( self->ssl, ret );
    if ( err != SSL_ERROR_NONE )
    {
    	Py_DECREF( buf );
    	handle_ssl_errors( self->ssl, err, ret );
    	return NULL;
    }


    if ( ret != bufsiz && _PyString_Resize( &buf, ret ) < 0 )
    {
		Py_DECREF( buf );
        return NULL;
    }
    return buf;
}
*/

static char ssl_Connection_renegotiate_doc[] = "\n\
Renegotiate the session\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if the renegotiation can be started, false otherwise\n\
";
static PyObject *
ssl_Connection_renegotiate( ssl_ConnectionObj * self, PyObject * args )
{
    int ret;

    if ( !PyArg_ParseTuple( args, ":renegotiate" ) )
        return NULL;

    OBJ_BEGIN_THREADS( self );
    ret = SSL_renegotiate( self->ssl );
    OBJ_END_THREADS( self );

    if ( PyErr_Occurred(  ) )
    {
        flush_error_queue(  );
        return NULL;
    }

    return PyInt_FromLong( ( long ) ret );
}

static void
helper_treatHandshakeError( ssl_ConnectionObj * conn, int err, int ret )
{
    PyObject *errlist, *tuple;
    char readableError[512], sslExtraError[100];

    switch ( err )
    {
        /*
         * Strange as it may seem, ZeroReturn is not an error per se. It means
         * that the SSL Connection has been closed correctly (note, not the
         * transport layer!), i.e. closure alerts have been exchanged. This is
         * an exception since
         *  + There's an SSL "error" code for it
         *  + You have to deal with it in any case, close the transport layer
         *    etc
         */
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_X509_LOOKUP:
    case SSL_ERROR_SYSCALL:
        handle_ssl_errors( conn->ssl, err, ret );
        return;

    }

    if ( conn->handshakeErrorId != X509_V_OK )
        sprintf( sslExtraError, ": %s",
                 X509_verify_cert_error_string( conn->handshakeErrorId ) );
    else
        sslExtraError[0] = 0;

    if ( conn->context->clientMethod )
        if ( !conn->remoteCertVerified )
            sprintf( readableError,
                     "Remote certificate hasn't been accepted%s",
                     sslExtraError );
        else
            sprintf( readableError,
                     "Your certificate is invalid%s", sslExtraError );
    else
        sprintf( readableError, "Handshake failed%s", sslExtraError );

    errlist = PyList_New( 0 );
    while ( ( err = (int)ERR_get_error(  ) ) != 0 )
    {
        tuple = Py_BuildValue( "(ssss)", readableError,
                               ERR_lib_error_string( err ),
                               ERR_func_error_string( err ),
                               ERR_reason_error_string( err ) );
        PyList_Append( errlist, tuple );
        Py_DECREF( tuple );
    }
    PyErr_SetObject( ssl_Error, errlist );
    Py_DECREF( errlist );

}

static char ssl_Connection_do_handshake_doc[] = "\n\
Perform an SSL handshake (usually called after renegotiate() or one of\n\
set_*_state()). This can raise the same exceptions as send and recv.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   None.\n\
";
static PyObject *
ssl_Connection_do_handshake( ssl_ConnectionObj * self, PyObject * args )
{
    int ret, err;

    if ( !PyArg_ParseTuple( args, ":do_handshake" ) )
        return NULL;

    OBJ_BEGIN_THREADS( self );
    ret = SSL_do_handshake( self->ssl );
    OBJ_END_THREADS( self );

    if ( PyErr_Occurred() )
    {
        flush_error_queue();
        return NULL;
    }

    err = SSL_get_error( self->ssl, ret );
    if ( err == SSL_ERROR_NONE )
    {
    	Py_RETURN_NONE;
    }
    else
    {
        helper_treatHandshakeError( self, err, ret );
        flush_error_queue();
        return NULL;
    }
}

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x00907000L
static char ssl_Connection_renegotiate_pending_doc[] = "\n\
Check if there's a renegotiation in progress, it will return false once\n\
a renegotiation is finished.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Whether there's a renegotiation in progress\n\
";
static PyObject *
ssl_Connection_renegotiate_pending( ssl_ConnectionObj *
                                    self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":renegotiate_pending" ) )
        return NULL;

    return PyInt_FromLong( ( long ) SSL_renegotiate_pending( self->ssl ) );
}
#endif

static char ssl_Connection_total_renegotiations_doc[] = "\n\
Find out the total number of renegotiations.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The number of renegotiations.\n\
";
static PyObject *
ssl_Connection_total_renegotiations( ssl_ConnectionObj *
                                     self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":total_renegotiations" ) )
        return NULL;

    return PyInt_FromLong( SSL_total_renegotiations( self->ssl ) );
}

static char ssl_Connection_set_accept_state_doc[] = "\n\
Set the connection to work in server mode. The handshake will be handled\n\
automatically by read/write.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   None\n\
";
static PyObject *
ssl_Connection_set_accept_state( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":set_accept_state" ) )
        return NULL;

    SSL_set_accept_state( self->ssl );

    Py_RETURN_NONE;
}

static char ssl_Connection_set_connect_state_doc[] = "\n\
Set the connection to work in client mode. The handshake will be handled\n\
automatically by read/write.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   None\n\
";
static PyObject *
ssl_Connection_set_connect_state( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":set_connect_state" ) )
        return NULL;

    SSL_set_connect_state( self->ssl );

    Py_RETURN_NONE;
}

static char ssl_Connection_connect_doc[] = "\n\
Connect to remote host and set up client-side SSL\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
             addr - A remote address\n\
Returns:   What the socket's connect method returns\n\
";
static PyObject *
ssl_Connection_connect( ssl_ConnectionObj * self, PyObject * args )
{
    PyObject *meth, *ret;

    if ( ( meth =
           PyObject_GetAttrString( self->socket, "connect" ) ) == NULL )
        return NULL;

    SSL_set_connect_state( self->ssl );

    ret = PyEval_CallObject( meth, args );
    Py_DECREF( meth );
    if ( ret == NULL )
        return NULL;

    return ret;
}

static char ssl_Connection_connect_ex_doc[] = "\n\
Connect to remote host and set up client-side SSL. Note that if the socket's\n\
connect_ex method doesn't return 0, SSL won't be initialized.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
             addr - A remove address\n\
Returns:   What the socket's connect_ex method returns\n\
";
static PyObject *
ssl_Connection_connect_ex( ssl_ConnectionObj * self, PyObject * args )
{
    PyObject *meth, *ret;

    if ( ( meth =
           PyObject_GetAttrString( self->socket, "connect_ex" ) ) == NULL )
        return NULL;

    SSL_set_connect_state( self->ssl );

    ret = PyEval_CallObject( meth, args );
    Py_DECREF( meth );
    if ( ret == NULL )
        return NULL;
    if ( PyInt_Check( ret ) && PyInt_AsLong( ret ) != 0 )
        return ret;

    return ret;
}

static char ssl_Connection_accept_doc[] = "\n\
Accept incoming connection and set up SSL on it\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   A (conn,addr) pair where conn is a Connection and addr is an\n\
           address\n\
";
static PyObject *
ssl_Connection_accept( ssl_ConnectionObj * self, PyObject * args )
{
    PyObject *tuple, *socket, *address, *meth;
    ssl_ConnectionObj *conn;

    if ( ( meth = PyObject_GetAttrString( self->socket, "accept" ) ) == NULL )
        return NULL;
    tuple = PyEval_CallObject( meth, args );

    Py_DECREF( meth );
    if ( tuple == NULL )
        return NULL;

    socket = PyTuple_GetItem( tuple, 0 );
    Py_INCREF( socket );
    address = PyTuple_GetItem( tuple, 1 );
    Py_INCREF( address );
    Py_DECREF( tuple );

    conn = ssl_Connection_New( self->context, socket );
    Py_DECREF( socket );
    if ( conn == NULL )
    {
        Py_DECREF( address );
        return NULL;
    }

    SSL_set_accept_state( conn->ssl );

    tuple = Py_BuildValue( "(OO)", conn, address );

    Py_DECREF( conn );
    Py_DECREF( address );

    return tuple;
}

static char ssl_Connection_shutdown_doc[] = "\n\
Send closure alert\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if the shutdown completed successfully (i.e. both sides\n\
           have sent closure alerts), false otherwise (i.e. you have to\n\
           wait for a ZeroReturnError on a recv() method call\n\
";
static PyObject *
ssl_Connection_shutdown( ssl_ConnectionObj * self, PyObject * args )
{
    int ret;

    if ( !PyArg_ParseTuple( args, ":shutdown" ) )
        return NULL;

    OBJ_BEGIN_THREADS( self );
    ret = SSL_shutdown( self->ssl );
    OBJ_END_THREADS( self );

    if ( PyErr_Occurred(  ) )
    {
        flush_error_queue(  );
        return NULL;
    }

    if ( ret < 0 )
    {
        exception_from_error_queue(  );
        return NULL;
    }
    else if ( ret > 0 )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static char ssl_Connection_get_cipher_list_doc[] = "\n\
Get the session cipher list\n\
WARNING: API change! This used to take an optional argument, and return a\n\
string.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   A list of cipher strings\n\
";
static PyObject *
ssl_Connection_get_cipher_list( ssl_ConnectionObj * self, PyObject * args )
{
    int idx = 0;
    const char *ret;
    PyObject *lst, *item;

    if ( !PyArg_ParseTuple( args, ":get_cipher_list" ) )
        return NULL;

    lst = PyList_New( 0 );
    while ( ( ret = SSL_get_cipher_list( self->ssl, idx ) ) != NULL )
    {
        item = PyString_FromString( ret );
        PyList_Append( lst, item );
        Py_DECREF( item );
        idx++;
    }
    return lst;
}

static char ssl_Connection_makefile_doc[] = "\n\
The makefile() method is not implemented, since there is no dup semantics\n\
for SSL connections\n\
XXX: Return self instead?\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   NULL\n\
";
static PyObject *
ssl_Connection_makefile( ssl_ConnectionObj * self, PyObject * args )
{
    PyErr_SetString( PyExc_NotImplementedError,
                     "Cannot make file object of SSL.Connection" );
    return NULL;
}

static char ssl_Connection_get_app_data_doc[] = "\n\
Get application data\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The application data\n\
";
static PyObject *
ssl_Connection_get_app_data( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":get_app_data" ) )
        return NULL;

    Py_INCREF( self->app_data );
    return self->app_data;
}

static char ssl_Connection_set_app_data_doc[] = "\n\
Set application data\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be\n\
             data - The application data\n\
Returns:   None\n\
";
static PyObject *
ssl_Connection_set_app_data( ssl_ConnectionObj * self, PyObject * args )
{
    PyObject *data,*old;

    if ( !PyArg_ParseTuple( args, "O:set_app_data", &data ) )
        return NULL;

    old = self->app_data;
    Py_INCREF( data );
    self->app_data = data;
    Py_DECREF( old );

    Py_RETURN_NONE;
}

static char ssl_Connection_state_string_doc[] = "\n\
Get a verbose state description\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   A string representing the state\n\
";
static PyObject *
ssl_Connection_state_string( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":state_string" ) )
        return NULL;

    return PyString_FromString( SSL_state_string_long( self->ssl ) );
}

static char ssl_Connection_sock_shutdown_doc[] = "\n\
See shutdown(2)\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be whatever the\n\
                  socket's shutdown() method expects\n\
Returns:   What the socket's shutdown() method returns\n\
";
static PyObject *
ssl_Connection_sock_shutdown( ssl_ConnectionObj * self, PyObject * args )
{
    PyObject *meth, *ret;

    if ( ( meth =
           PyObject_GetAttrString( self->socket, "shutdown" ) ) == NULL )
        return NULL;
    ret = PyEval_CallObject( meth, args );
    Py_DECREF( meth );
    return ret;
}

static char ssl_Connection_get_peer_certificate_doc[] = "\n\
Retrieve the other side's certificate (if any)\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The peer's certificate\n\
";
static PyObject *
ssl_Connection_get_peer_certificate( ssl_ConnectionObj *
                                     self, PyObject * args )
{
    X509 *cert;

    if ( !PyArg_ParseTuple( args, ":get_peer_certificate" ) )
        return NULL;

    cert = SSL_get_peer_certificate( self->ssl );
    if ( cert != NULL )
    {
        return ( PyObject * ) crypto_X509_New( cert, 1 );
    }
    else
    {
    	Py_RETURN_NONE;
    }
}

static char ssl_Connection_get_peer_certificate_chain_doc[] = "\n\
Retrieve the other side's certificate chain (if any)\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   List with the peer's certificate chain\n\
";
static PyObject *
ssl_Connection_get_peer_certificate_chain( ssl_ConnectionObj *
                                           self, PyObject * args )
{
    STACK_OF( X509 ) * certStack;
    X509 *cert;
    PyObject *list;
    int numCert, i;

    if ( !PyArg_ParseTuple( args, ":get_peer_certificate_chain" ) )
        return NULL;

    certStack = SSL_get_peer_cert_chain( self->ssl );
    if ( certStack != NULL )
    {
        numCert = sk_X509_num( certStack );
        if ( numCert < 0 )
            numCert = 0;
        list = PyList_New( numCert );
        for ( i = 0; i < numCert; i++ )
        {
            cert = sk_X509_value( certStack, i );
            if ( !cert )
            {
                Py_DECREF( list );
                exception_from_error_queue(  );
                return NULL;
            }
            if ( PyList_SetItem
                 ( list, i,
                   ( PyObject * ) crypto_X509_New( cert, 0 ) ) == -1 )
            {
                Py_DECREF( list );
                return NULL;
            }
        }
        return list;
    }
    else
    {
    	Py_RETURN_NONE;
    }
}

static char ssl_Connection_want_read_doc[] = "\n\
Checks if more data has to be read from the transport layer to complete an\n\
operation.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True iff more data has to be read\n\
";
static PyObject *
ssl_Connection_want_read( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":want_read" ) )
        return NULL;

    return PyInt_FromLong( ( long ) SSL_want_read( self->ssl ) );
}

static char ssl_Connection_want_write_doc[] = "\n\
Checks if there is data to write to the transport layer to complete an\n\
operation.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True iff there is data to write\n\
";
static PyObject *
ssl_Connection_want_write( ssl_ConnectionObj * self, PyObject * args )
{
    if ( !PyArg_ParseTuple( args, ":want_write" ) )
        return NULL;

    return PyInt_FromLong( ( long ) SSL_want_write( self->ssl ) );
}

static char ssl_Connection_get_session_doc[] = "\n\
Get connection session.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The session for the connection.\n\
";
static PyObject *
ssl_Connection_get_session( ssl_ConnectionObj * self, PyObject * args )
{
    ssl_SessionObj *session;

    if ( !PyArg_ParseTuple( args, ":get_session" ) )
        return NULL;

    session = ssl_Session_New(  );

    session->session = SSL_get1_session( self->ssl );

    return ( PyObject * ) session;
}

static char ssl_Connection_set_session_doc[] = "\n\
Sets the session to use for the connection.\n\
Session should be specified before performing\n\
connection in order to be used\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
		     session - The session to use\n\
Returns:   Return value from underlying C call.\n\
";
static PyObject *
ssl_Connection_set_session( ssl_ConnectionObj * self, PyObject * args )
{
    ssl_SessionObj *session;
    int returnValue = 0;

    if ( !PyArg_ParseTuple
         ( args, "O!:set_session", &ssl_Session_Type, &session ) )
        return NULL;

    if ( session->session != NULL )
    {
        returnValue = SSL_set_session( self->ssl, session->session );
    }

    return PyInt_FromLong( ( long ) returnValue );
}

static char ssl_Connection_session_reused_doc[] = "\n\
Checks if the session has been reused.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if the session has been reused\n\
";
static PyObject *
ssl_Connection_session_reused( ssl_ConnectionObj * self, PyObject * args )
{

    if ( !PyArg_ParseTuple( args, ":session_reused" ) )
        return NULL;

    return PyInt_FromLong( ( long ) SSL_session_reused( self->ssl ) );
}

static char ssl_Connection_get_socket_doc[] = "\n\
Returns underlying socket. This socket performs no SSL\n\
operations when used alone.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Underlaying socket.\n\
";
static PyObject *
ssl_Connection_get_socket( ssl_ConnectionObj * self, PyObject * args )
{

    if ( !PyArg_ParseTuple( args, ":get_socket" ) )
        return NULL;

    Py_INCREF( self->socket );
    return self->socket;
}

static char ssl_Connection_get_last_error_doc[] = "\n\
Returns last SSL error.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Last SSL error.\n\
";
static PyObject *
ssl_Connection_get_last_error( ssl_ConnectionObj * self, PyObject * args )
{

    if ( !PyArg_ParseTuple( args, ":get_last_error" ) )
        return NULL;

    return Py_BuildValue( "s", ERR_error_string( ERR_get_error(  ), NULL ) );
}

static char ssl_Connection_get_shutdown_doc[] = "\n\
Returns the SSL shutdown status.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   SSL shutdown mode.\n\
";
static PyObject *
ssl_Connection_get_shutdown( ssl_ConnectionObj * self, PyObject * args )
{

    if ( !PyArg_ParseTuple( args, ":get_shutdown" ) )
        return NULL;

    return Py_BuildValue( "i", SSL_get_shutdown( self->ssl ) );
}

static char ssl_Connection_set_shutdown_doc[] = "\n\
Sets the SSL shutdown status.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be empty\n\
		     shutdownMode - SSL shutdown status to be set.\n\
Returns:   None\n\
";
static PyObject *
ssl_Connection_set_shutdown( ssl_ConnectionObj * self, PyObject * args )
{
    int shutdownMode = 0;

    if ( !PyArg_ParseTuple( args, "i:set_shutdown", &shutdownMode ) )
        return NULL;

    SSL_set_shutdown( self->ssl, shutdownMode );

    Py_RETURN_NONE;
}

static char ssl_Connection_peek_doc[] = "\n\
Read data from connection but don't remove it from the buffer.\n\
Posterior calls to peek or read will return the same data plus\n\
new one that may have arrived.\n\
\n\
Arguments: self - The Connection object\n\
           args - The Python argument tuple, should be:\n\
             bufsiz - The maximum number of bytes to read\n\
             flags  - (optional) Included for compatability with the socket\n\
                      API, the value is ignored\n\
Returns:   Data peeked.\n\
";
static PyObject *
ssl_Connection_peek( ssl_ConnectionObj * self, PyObject * args )
{
    int bufsiz, ret, err, flags;
    char *cbuf;
    PyObject *buf;

    if ( !PyArg_ParseTuple( args, "i|i:recv", &bufsiz, &flags ) )
        return NULL;

    buf = PyString_FromStringAndSize( NULL, bufsiz );
    if ( buf == NULL )
        return NULL;

    cbuf = PyString_AsString( buf );

    OBJ_BEGIN_THREADS( self );
    ret = SSL_peek( self->ssl, cbuf, bufsiz );
    OBJ_END_THREADS( self );

    if ( PyErr_Occurred(  ) )
    {
        Py_DECREF( buf );
        flush_error_queue(  );
        return NULL;
    }

    err = SSL_get_error( self->ssl, ret );
    if ( err == SSL_ERROR_NONE )
    {
        if ( ret != bufsiz && _PyString_Resize( &buf, ret ) < 0 )
        return NULL;
        return buf;
    }
    else
    {
        handle_ssl_errors( self->ssl, err, ret );
        Py_DECREF( buf );
        return NULL;
    }
}

/*
 * Member methods in the Connection object
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)ssl_Connection_name, METH_VARARGS }
 * for convenience
 * ADD_ALIAS(name,real) creates an "alias" of the ssl_Connection_real
 * function with the name 'name'
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)ssl_Connection_##name, METH_VARARGS, ssl_Connection_##name##_doc }
#define ADD_ALIAS(name,real)    \
    { #name, (PyCFunction)ssl_Connection_##real, METH_VARARGS, ssl_Connection_##real##_doc }
static PyMethodDef ssl_Connection_methods[] = {
    ADD_METHOD( get_context ),
    ADD_METHOD( pending ),
    ADD_METHOD( send ),
    ADD_ALIAS( write, send ),
    ADD_METHOD( sendall ),
    ADD_METHOD( recv ),
    ADD_ALIAS( read, recv ),
    ADD_METHOD( renegotiate ),
    ADD_METHOD( do_handshake ),
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x00907000L
    ADD_METHOD( renegotiate_pending ),
#endif
    ADD_METHOD( total_renegotiations ),
    ADD_METHOD( connect ),
    ADD_METHOD( connect_ex ),
    ADD_METHOD( accept ),
    ADD_METHOD( shutdown ),
    ADD_METHOD( get_cipher_list ),
    ADD_METHOD( makefile ),
    ADD_METHOD( get_app_data ),
    ADD_METHOD( set_app_data ),
    ADD_METHOD( state_string ),
    ADD_METHOD( sock_shutdown ),
    ADD_METHOD( get_peer_certificate ),
    ADD_METHOD( get_peer_certificate_chain ),
    ADD_METHOD( want_read ),
    ADD_METHOD( want_write ),
    ADD_METHOD( set_accept_state ),
    ADD_METHOD( set_connect_state ),
    ADD_METHOD( get_session ),
    ADD_METHOD( set_session ),
    ADD_METHOD( session_reused ),
    ADD_METHOD( get_socket ),
    ADD_METHOD( get_last_error ),
    ADD_METHOD( get_shutdown ),
    ADD_METHOD( set_shutdown ),
    ADD_METHOD( peek ),
    {NULL, NULL}
};

#undef ADD_ALIAS
#undef ADD_METHOD


/*
 * Constructor for Connection objects
 *
 * Arguments: ctx  - An SSL Context to use for this connection
 *            sock - The socket to use for transport layer
 * Returns:   The newly created Connection object
 */
ssl_ConnectionObj *
ssl_Connection_New( ssl_ContextObj * ctx, PyObject * sock )
{
    ssl_ConnectionObj *self;
    int fd;

    self = PyObject_GC_New( ssl_ConnectionObj, &ssl_Connection_Type );
    if ( self == NULL )
        return NULL;

    self->remoteCertVerified = 0;
    self->handshakeErrorId = X509_V_OK;

    Py_INCREF( ctx );
    self->context = ctx;

    Py_INCREF( sock );
    self->socket = sock;

    self->ssl = NULL;

    Py_INCREF( Py_None );
    self->app_data = Py_None;

    self->tstate = NULL;

    fd = PyObject_AsFileDescriptor( self->socket );
    if ( fd < 0 )
    {
        Py_CLEAR( self->context );
        Py_CLEAR( self->socket );
        Py_CLEAR( self->app_data );
        PyObject_GC_Del( self );
        return NULL;
    }

    self->ssl = SSL_new( self->context->ctx );
    SSL_set_app_data( self->ssl, self );
    SSL_set_fd( self->ssl, ( SOCKET_T ) fd );

    PyObject_GC_Track( self );

    return self;
}

/*
 * Find attribute
 *
 * Arguments: self - The Connection object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
ssl_Connection_getattr( ssl_ConnectionObj * self, char *name )
{
    PyObject *meth;

    meth = Py_FindMethod( ssl_Connection_methods, ( PyObject * ) self, name );

    if ( PyErr_Occurred(  )
         && PyErr_ExceptionMatches( PyExc_AttributeError ) )
    {
        PyErr_Clear(  );
        /* Try looking it up in the "socket" instead. */
        meth = PyObject_GetAttrString( self->socket, name );
    }

    return meth;
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
ssl_Connection_traverse( ssl_ConnectionObj * self, visitproc visit,
                         void *arg )
{
    Py_VISIT( self->context );
    Py_VISIT( self->socket );
    Py_VISIT( self->app_data );
    return 0;
}

/*
 * Decref all contained objects and zero the pointers.
 *
 * Arguments: self - The Connection object
 * Returns:   Always 0.
 */
static int
ssl_Connection_clear( ssl_ConnectionObj * self )
{
    Py_CLEAR( self->context );
    Py_CLEAR( self->socket );
    Py_CLEAR( self->app_data );
    return 0;
}

/*
 * Deallocate the memory used by the Connection object
 *
 * Arguments: self - The Connection object
 * Returns:   None
 */
static void
ssl_Connection_dealloc( ssl_ConnectionObj * self )
{
    PyObject_GC_UnTrack( self );

    if ( self->ssl != NULL )
        SSL_free( self->ssl );

    ssl_Connection_clear( self );

    PyObject_GC_Del( self );
}

PyTypeObject ssl_Connection_Type = {
    PyObject_HEAD_INIT( NULL ) 0,
    "Connection",
    sizeof( ssl_ConnectionObj ),
    0,
    ( destructor ) ssl_Connection_dealloc,
    NULL,                       /* print */
    ( getattrfunc ) ssl_Connection_getattr,
    NULL,                       /* setattr */
    NULL,                       /* compare */
    NULL,                       /* repr */
    NULL,                       /* as_number */
    NULL,                       /* as_sequence */
    NULL,                       /* as_mapping */
    NULL,                       /* hash */
    NULL,                       /* call */
    NULL,                       /* str */
    NULL,                       /* getattro */
    NULL,                       /* setattro */
    NULL,                       /* as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    NULL,                       /* doc */
    ( traverseproc ) ssl_Connection_traverse,
    ( inquiry ) ssl_Connection_clear,
};


/*
 * Initiailze the Connection part of the SSL sub module
 *
 * Arguments: dict - Dictionary of the OpenSSL.SSL module
 * Returns:   1 for success, 0 otherwise
 */
int
init_ssl_connection( PyObject * dict )
{
    ssl_Connection_Type.ob_type = &PyType_Type;
    Py_INCREF( &ssl_Connection_Type );
    if ( PyDict_SetItemString
         ( dict, "ConnectionType",
           ( PyObject * ) & ssl_Connection_Type ) != 0 )
        return 0;

    return 1;
}
