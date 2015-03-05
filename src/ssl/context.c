#include <Python.h>
#define SSL_MODULE
#include "ssl.h"

/*
 * CALLBACKS
 *
 * Callbacks work like this: We provide a "global" callback in C which
 * transforms the arguments into a Python argument tuple and calls the
 * corresponding Python callback, and then parsing the return value back into
 * things the C function can return.
 *
 * Three caveats:
 *  + How do we find the Context object where the Python callbacks are stored?
 *  + What about multithreading and execution frames?
 *  + What about Python callbacks that raise exceptions?
 *
 * The solution to the first issue is trivial if the callback provides
 * "userdata" functionality. Since the only callbacks that don't provide
 * userdata do provide a pointer to an SSL structure, we can associate an SSL
 * object and a Connection one-to-one via the SSL_set/get_app_data()
 * functions.
 *
 * The solution to the other issue is to rewrite the Py_BEGIN_ALLOW_THREADS
 * macro allowing it (or rather a new macro) to specify where to save the
 * thread state (in our case, as a member of the Connection/Context object) so
 * we can retrieve it again before calling the Python callback.
 */

/*
 * Globally defined passphrase callback.
 *
 * Arguments: buf    - Buffer to store the returned passphrase in
 *            maxlen - Maximum length of the passphrase
 *            verify - If true, the passphrase callback should ask for a
 *                     password twice and verify they're equal. If false, only
 *                     ask once.
 *            arg    - User data, always a Context object
 * Returns:   The length of the password if successful, 0 otherwise
 */
static int global_passphrase_callback( char *buf, int maxlen, int verify,
		void *arg )
{
	int len;

	char *str;

	PyObject *argv, *ret = NULL;

	ssl_ContextObj *ctx = (ssl_ContextObj *) arg;

	/* The Python callback is called with a (maxlen,verify,userdata) tuple
	 */
	argv = Py_BuildValue("(iiO)", maxlen, verify, ctx->passphrase_userdata);
	if ( ctx->tstate != NULL )
	{
		/* We need to get back our thread state before calling the
		 callback */
		ret = PyEval_CallObject(ctx->passphrase_callback, argv);
	}
	else
	{
		ret = PyEval_CallObject(ctx->passphrase_callback, argv);
	}
	Py_DECREF(argv);

	if ( ret == NULL )
	{
		return 0;
	}

	if ( !PyObject_IsTrue(ret) )
	{
		Py_DECREF(ret);
		return 0;
	}

	if ( !PyString_Check(ret) )
	{
		Py_DECREF(ret);
		return 0;
	}

	len = PyString_Size(ret);
	if ( len > maxlen )
		len = maxlen;

	str = PyString_AsString(ret);
	strncpy(buf, str, len);
	Py_XDECREF(ret);

	return len;
}

/*
 * Globally defined verify callback
 *
 * Arguments: ok       - True everything is OK "so far", false otherwise
 *            x509_ctx - Contains the certificate being checked, the current
 *                       error number and depth, and the Connection we're
 *                       dealing with
 * Returns:   True if everything is okay, false otherwise
 */
static int global_verify_callback( int ok, X509_STORE_CTX * x509_ctx )
{
	PyObject *argv, *ret;

	SSL *ssl;

	ssl_ConnectionObj *conn;

	crypto_X509Obj *cert;

	X509 *x509;

	int errnum = X509_STORE_CTX_get_error(x509_ctx);

	int errdepth = X509_STORE_CTX_get_error_depth(x509_ctx);

#ifdef GSI_HANDSHAKE_DEBUG
	logMsg( 0, "GVC %d errnum %d errdepth", errnum, errdepth );
#endif

	ssl = (SSL *) X509_STORE_CTX_get_app_data(x509_ctx);
	conn = (ssl_ConnectionObj *) SSL_get_app_data(ssl);
	OBJ_END_THREADS( conn );
	Py_INCREF( conn );

	if ( conn->context->verify_callback != Py_None )
	{
		x509 = X509_STORE_CTX_get_current_cert(x509_ctx);

		cert = crypto_X509_New(x509, 0);
		argv = Py_BuildValue("(OOiii)", (PyObject *) conn, (PyObject *) cert,
				errnum, errdepth, ok);
		Py_DECREF(cert);
		/* We need to get back our thread state before calling the callback */
		ret = PyEval_CallObject(conn->context->verify_callback, argv);
		Py_DECREF(argv);

		if ( ret == NULL )
		{
			ok = 0;
		}
		else
		{
			if ( PyObject_IsTrue(ret) )
			{
				X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
				ok = 1;
			}
			else
				ok = 0;

			Py_DECREF(ret);
		}
	}

	//Set the remove verification flag in the end
	if ( errdepth == 0 && ok )
	{
		conn->remoteCertVerified = 1;
	}

	Py_DECREF( conn );
	OBJ_BEGIN_THREADS( conn );

	return ok;
}

/*
 * Globally gsi enabled defined verify callback
 *
 * Arguments: ok       - True everything is OK "so far", false otherwise
 *            x509_ctx - Contains the certificate being checked, the current
 *                       error number and depth, and the Connection we're
 *                       dealing with
 * Returns:   True if everything is okay, false otherwise
 */
static int gsi_wrapper_global_verify_callback( int ok,
		X509_STORE_CTX * x509_ctx )
{
	//Call gsi verification
	ok = gsiVerifyCallback(ok, x509_ctx);
	//Call normal callback
	return global_verify_callback(ok, x509_ctx);
}

/*
 * Globally defined info callback
 *
 * Arguments: ssl   - The Connection
 *            where - The part of the SSL code that called us
 *            _ret  - The return code of the SSL function that called us
 * Returns:   None
 */
static void global_info_callback( const SSL * ssl, int where, int _ret )
{
	ssl_ConnectionObj *conn = (ssl_ConnectionObj *) SSL_get_app_data(ssl);

	PyObject *argv, *ret;


	argv = Py_BuildValue("(Oii)", (PyObject *) conn, where, _ret);
	/* We need to get back our thread state before calling the
	 callback */
	ret = PyEval_CallObject(conn->context->info_callback, argv);
	if ( ret == NULL )
		PyErr_Clear();
	else
		Py_DECREF(ret);
	Py_DECREF(argv);

	return;
}

static char
		ssl_Context_load_verify_locations_path_doc[] =
				"\n\
		Let SSL know where we can find trusted certificates for the certificate\n\
		chain\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		cadir - Which directory we can find the certificates\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_load_verify_locations_path( ssl_ContextObj * self, PyObject * args )
{
	char *cadir;

	if ( !PyArg_ParseTuple(args, "s:load_verify_locations_path", &cadir) )
		return NULL;

	if ( !SSL_CTX_load_verify_locations(self->ctx, NULL, cadir) )
	{
		exception_from_error_queue();
		return NULL;
	}

	Py_RETURN_NONE;
}

static char
		ssl_Context_load_verify_locations_doc[] =
				"\n\
		Let SSL know where we can find trusted certificates for the certificate\n\
		chain\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		cafile - Which file we can find the certificates\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_load_verify_locations( ssl_ContextObj * self, PyObject * args )
{
	char *cafile;

	if ( !PyArg_ParseTuple(args, "s:load_verify_locations", &cafile) )
		return NULL;

	if ( !SSL_CTX_load_verify_locations(self->ctx, cafile, NULL) )
	{
		exception_from_error_queue();
		return NULL;
	}

	Py_RETURN_NONE;
}

static char
		ssl_Context_set_passwd_cb_doc[] =
				"\n\
		Set the passphrase callback\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		callback - The Python callback to use\n\
		userdata - (optional) A Python object which will be given as\n\
		argument to the callback\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_passwd_cb( ssl_ContextObj * self, PyObject * args )
{
	PyObject *callback = NULL, *userdata = NULL, *old;

	if ( !PyArg_ParseTuple(args, "O|O:set_passwd_cb", &callback, &userdata) )
		return NULL;

	if ( !PyCallable_Check(callback) )
	{
		PyErr_SetString(PyExc_TypeError, "expected PyCallable");
		return NULL;
	}

	if ( !userdata )
		userdata = Py_None;

	old = self->passphrase_callback;
	Py_INCREF( callback );
	self->passphrase_callback = callback;
	Py_DECREF( old );
	SSL_CTX_set_default_passwd_cb(self->ctx, global_passphrase_callback);

	old = self->passphrase_userdata;
	Py_INCREF( userdata );
	self->passphrase_userdata = userdata;
	Py_DECREF( old );
	SSL_CTX_set_default_passwd_cb_userdata(self->ctx, (void *) self);

	Py_RETURN_NONE;
}

static char
		ssl_Context_use_certificate_chain_file_doc[] =
				"\n\
		Load a certificate chain from a file\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		certfile - The name of the certificate chain file\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_certificate_chain_file( ssl_ContextObj * self, PyObject * args )
{
	char *certfile;

	if ( !PyArg_ParseTuple(args, "s:use_certificate_chain_file", &certfile) )
		return NULL;

	if ( !SSL_CTX_use_certificate_chain_file(self->ctx, certfile) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_use_certificate_chain_string_doc[] =
				"\n\
		Load a certificate chain from a file\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		certstring - The certificate chain in PEM format\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_certificate_chain_string( ssl_ContextObj * self,
		PyObject * args )
{
	char *certString;
	BIO *mem;
	int ret = 0;
	unsigned long err = 0;

	X509 *x509 = NULL;

	if ( !PyArg_ParseTuple(args, "s:use_certificate_chain_string", &certString) )
		return NULL;

	mem = BIO_new_mem_buf(certString, -1);

	x509 = PEM_read_bio_X509(mem, NULL, self->ctx->default_passwd_callback,
			self->ctx->default_passwd_callback_userdata);
	if ( x509 == NULL )
	{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
		exception_from_error_queue();
		BIO_free(mem);
		return NULL;
	}

	ret = SSL_CTX_use_certificate(self->ctx, x509);

	if ( (err = ERR_peek_error()) != 0 )
	{
		ret = 0; /* Key/certificate mismatch doesn't imply ret==0 ... */
	}

	X509_free(x509);

	if ( ret )
	{
		/* If we could set up our certificate, now proceed to
		 * the CA certificates.
		 */

		if ( self->ctx->extra_certs != NULL )
		{
			sk_X509_pop_free(self->ctx->extra_certs, X509_free);
			self->ctx->extra_certs = NULL;
		}

		while ( (x509 = PEM_read_bio_X509(mem, NULL,
				self->ctx->default_passwd_callback,
				self->ctx-> default_passwd_callback_userdata)) != NULL )
		{
			ret = SSL_CTX_add_extra_chain_cert(self->ctx, x509);
			if ( !ret )
			{
				X509_free(x509);
				exception_from_error_queue();
				BIO_free(mem);
				return NULL;
			}
			/* Note that we must not free ca x509 if it was successfully
			 * added to the chain (while we must free the main
			 * certificate, since its reference count is increased
			 * by SSL_CTX_use_certificate). */
		}
		/* When the while loop ends, it's usually just EOF. */
		err = ERR_peek_last_error();
		if ( ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err)
				== PEM_R_NO_START_LINE )
			ERR_clear_error();
		else
			ret = 0; /* some real error */
	}

	BIO_free(mem);

	if ( !ret )
	{
		exception_from_error_queue();
		return NULL;
	}

	Py_RETURN_NONE;
}

static char
		ssl_Context_use_certificate_file_doc[] =
				"\n\
		Load a certificate from a file\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		certfile - The name of the certificate file\n\
		filetype - (optional) The encoding of the file, default is PEM\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_certificate_file( ssl_ContextObj * self, PyObject * args )
{
	char *certfile;

	int filetype = SSL_FILETYPE_PEM;

	if ( !PyArg_ParseTuple(args, "s|i:use_certificate_file", &certfile,
			&filetype) )
		return NULL;

	if ( !SSL_CTX_use_certificate_file(self->ctx, certfile, filetype) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_use_certificate_doc[] =
				"\n\
		Load a certificate from a X509 object\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		cert - The X509 object\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_certificate( ssl_ContextObj * self, PyObject * args )
{
	static PyTypeObject *crypto_X509_type = NULL;

	crypto_X509Obj *cert;

	/* We need to check that cert really is an X509 object before we deal
	 with it. The problem is we can't just quickly verify the type
	 (since that comes from another module). This should do the trick
	 (reasonably well at least): Once we have one verified object, we
	 use it's type object for future comparisons. */

	if ( !crypto_X509_type )
	{
		if ( !PyArg_ParseTuple(args, "O:use_certificate", &cert) )
			return NULL;

		if ( strcmp(cert->ob_type->tp_name, "X509") != 0
				|| cert->ob_type->tp_basicsize != sizeof(crypto_X509Obj) )
		{
			PyErr_SetString(PyExc_TypeError, "Expected an X509 object");
			return NULL;
		}

		crypto_X509_type = cert->ob_type;
	}
	else if ( !PyArg_ParseTuple(args, "O!:use_certificate", crypto_X509_type,
			&cert) )
		return NULL;

	if ( !SSL_CTX_use_certificate(self->ctx, cert->x509) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_use_certificate_chain_doc[] =
				"\n\
		Load a certificate chain from a list of X509 object\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		certList - List of X509 objects\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_certificate_chain( ssl_ContextObj * self, PyObject * args )
{
	static PyTypeObject *crypto_X509_Type = NULL;

	crypto_X509Obj *cert;

	PyObject *certList;

	int i, numContents;

	/* We need to check that cert really is an X509 object before we deal
	 with it. The problem is we can't just quickly verify the type
	 (since that comes from another module). This should do the trick
	 (reasonably well at least): Once we have one verified object, we
	 use it's type object for future comparisons. */

	if ( !PyArg_ParseTuple(args, "O:use_certificate_chain", &certList) )
		return NULL;

	certList = PySequence_Fast(certList, "Expected a sequence object");
	if ( !certList )
		return NULL;

	numContents = PySequence_Fast_GET_SIZE(certList);
	if ( numContents < 0 )
	{
		Py_DECREF(certList);
		PyErr_SetString(PyExc_TypeError, "Can't get length of sequence");
		return NULL;
	}
	for ( i = 0; i < numContents; i++ )
	{
		cert = (crypto_X509Obj *) PySequence_Fast_GET_ITEM(certList, i);
		if ( !crypto_X509_Type )
		{
			if ( strcmp(cert->ob_type->tp_name, "X509") != 0
					|| cert->ob_type->tp_basicsize != sizeof(crypto_X509Obj) )
			{
				Py_DECREF(certList);
				PyErr_SetString(PyExc_TypeError, "Expected an X509 object");
				return NULL;
			}
			crypto_X509_Type = cert->ob_type;
		}
		else if ( cert->ob_type != crypto_X509_Type )
		{
			Py_DECREF(certList);
			PyErr_SetString(PyExc_TypeError,
					"Contents of sequence need to be X509 objects");
			return NULL;
		}
		if ( i == 0 )
		{
			if ( !SSL_CTX_use_certificate(self->ctx, cert->x509) )
			{
				Py_DECREF(certList);
				exception_from_error_queue();
				return NULL;
			}
		}
		else
		{
			if ( !SSL_CTX_add_extra_chain_cert(self->ctx, cert->x509) )
			{
				Py_DECREF(certList);
				exception_from_error_queue();
				return NULL;
			}
		}
	}

	Py_RETURN_NONE;
}

static char
		ssl_Context_use_privatekey_string_doc[] =
				"\n\
		Load a private key from a file\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		keystring  - The string with the key\n\
		filetype - (optional) The encoding of the file, default is PEM\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_privatekey_string( ssl_ContextObj * self, PyObject * args )
{
	char *keystring;
	int ret;

	int filetype = SSL_FILETYPE_PEM;

	EVP_PKEY *pkey = NULL;

	BIO *mem = NULL;

	if ( !PyArg_ParseTuple(args, "s|i:use_privatekey_string", &keystring,
			&filetype) )
		return NULL;

	if ( filetype != SSL_FILETYPE_PEM )
	{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
		exception_from_error_queue();
		return NULL;
	}

	mem = BIO_new_mem_buf(keystring, -1);
	if ( mem == NULL )
	{
		exception_from_error_queue();
		return NULL;
	}
	pkey = PEM_read_bio_PrivateKey(mem, NULL,
			self->ctx->default_passwd_callback,
			self->ctx-> default_passwd_callback_userdata);
	if ( pkey == NULL )
	{
		exception_from_error_queue();
		BIO_free(mem);
		return NULL;
	}

	ret = SSL_CTX_use_PrivateKey(self->ctx, pkey);
	EVP_PKEY_free(pkey);
	BIO_free(mem);

	if ( !ret )
	{
		exception_from_error_queue();
		return NULL;
	}

	Py_RETURN_NONE;
}

static char
		ssl_Context_use_privatekey_file_doc[] =
				"\n\
		Load a private key from a file\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		keyfile  - The name of the key file\n\
		filetype - (optional) The encoding of the file, default is PEM\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_privatekey_file( ssl_ContextObj * self, PyObject * args )
{
	char *keyfile;

	int filetype = SSL_FILETYPE_PEM, ret;

	if ( !PyArg_ParseTuple(args, "s|i:use_privatekey_file", &keyfile, &filetype) )
		return NULL;

	Py_BEGIN_ALLOW_THREADS;
	ret = SSL_CTX_use_PrivateKey_file(self->ctx, keyfile, filetype);
	Py_END_ALLOW_THREADS;

	if ( PyErr_Occurred() )
	{
		flush_error_queue();
		return NULL;
	}

	if ( !ret )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_use_privatekey_doc[] =
				"\n\
		Load a private key from a PKey object\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		pkey - The PKey object\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_use_privatekey( ssl_ContextObj * self, PyObject * args )
{
	static PyTypeObject *crypto_PKey_Type = NULL;

	crypto_PKeyObj *pkey;

	/* We need to check that cert really is a PKey object before we deal
	 with it. The problem is we can't just quickly verify the type
	 (since that comes from another module). This should do the trick
	 (reasonably well at least): Once we have one verified object, we
	 use it's type object for future comparisons. */

	if ( !PyArg_ParseTuple(args, "O:use_privatekey", &pkey) )
		return NULL;

	if ( !crypto_PKey_Type )
	{
		if ( strcmp(pkey->ob_type->tp_name, "PKey") != 0
				|| pkey->ob_type->tp_basicsize != sizeof(crypto_PKeyObj) )
		{
			PyErr_SetString(PyExc_TypeError, "Expected an PKey object");
			return NULL;
		}

		crypto_PKey_Type = pkey->ob_type;
	}
	else if ( pkey->ob_type != crypto_PKey_Type )
	{
		PyErr_SetString(PyExc_TypeError, "Expected a PKey object");
		return NULL;
	}

	if ( !SSL_CTX_use_PrivateKey(self->ctx, pkey->pkey) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_check_privatekey_doc[] =
				"\n\
		Check that the private key and certificate match up\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   None (raises an exception if something's wrong)\n\
		";

static PyObject *
ssl_Context_check_privatekey( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":check_privatekey") )
		return NULL;

	if ( !SSL_CTX_check_private_key(self->ctx) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_load_client_ca_doc[] =
				"\n\
		Load the trusted certificates that will be sent to the client (basically\n\
		telling the client \"These are the guys I trust\")\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		cafile - The name of the certificates file\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_load_client_ca( ssl_ContextObj * self, PyObject * args )
{
	PyObject *argObj, *certSequence;
	char *certPath;
	int numContents,i;
	STACK_OF(X509_NAME) *certNameStack, *tmpStack;
	X509_NAME *certName;

	if ( !PyArg_ParseTuple(args, "O:load_client_ca", &argObj) )
		return NULL;

	if ( PyString_Check(argObj) )
	{
		certPath = PyString_AsString(argObj);
		SSL_CTX_set_client_CA_list(self->ctx, SSL_load_client_CA_file(certPath));
		// ADRIFIX: Removed here -> Py_DECREF(argObj);
		Py_RETURN_NONE;
	}

	certSequence = PySequence_Fast(argObj, "Expected a sequence object");
	// ADRIFIX: Removed here -> Py_DECREF(argObj);
	if ( !certSequence )
		return NULL;

	numContents = PySequence_Fast_GET_SIZE(certSequence);
	certNameStack = sk_X509_NAME_new_null();
	for ( i = 0; i < numContents; i++ )
	{
		argObj = PySequence_Fast_GET_ITEM(certSequence, i);

		if ( ! PyString_Check( argObj ) )
		{
			continue;
		}
		certPath = PyString_AsString( argObj );
		tmpStack = SSL_load_client_CA_file( certPath );
		if( !tmpStack )
			continue;
		certName = sk_X509_NAME_pop( tmpStack );
		while( certName )
		{
			sk_X509_NAME_push( certNameStack, certName );
			certName = sk_X509_NAME_pop( tmpStack );
		}
		sk_X509_NAME_free( tmpStack );
	}
	Py_DECREF( certSequence );


	if( sk_X509_NAME_num( certNameStack ) > 0 )
	{
		SSL_CTX_set_client_CA_list(self->ctx, certNameStack);
	}

	Py_RETURN_NONE;

}

static char
		ssl_Context_set_session_id_doc[] =
				"\n\
		Set the session identifier, this is needed if you want to do session\n\
		resumption (which, ironically, isn't implemented yet)\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		buf - A Python object that can be safely converted to a string\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_session_id( ssl_ContextObj * self, PyObject * args )
{
	unsigned char *buf;

	int len;

	if ( !PyArg_ParseTuple(args, "s#:set_session_id", &buf, &len) )
		return NULL;

	if ( !SSL_CTX_set_session_id_context(self->ctx, buf, len) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		// SSL_CTX_set_session_cache_mode( self->ctx,
		// SSL_SESS_CACHE_SERVER );
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_set_verify_doc[] =
				"\n\
		Set the verify mode and verify callback\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		mode     - The verify mode, this is either SSL_VERIFY_NONE or\n\
		SSL_VERIFY_PEER combined with possible other flags\n\
		callback - The Python callback to use\n\
		enableGSI - Enable gsi authorization\n\
		optional:\n\
		gsiEnabled - Wether to enable gsi verification. True by default\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_verify( ssl_ContextObj * self, PyObject * args )
{
	int mode;

	int gsiEnable = 1;

	PyObject *callback = NULL, *old;

	if ( !PyArg_ParseTuple(args, "iO|i:set_verify", &mode, &callback,
			&gsiEnable) )
		return NULL;

	if ( !PyCallable_Check(callback) )
		callback = Py_None;

	old = self->verify_callback;
	Py_INCREF(callback);
	self->verify_callback = callback;
	Py_DECREF(old);

	if ( gsiEnable )
	{
		SSL_CTX_set_cert_verify_callback(self->ctx, gsiVerifyCertWrapper,
				(void *) NULL);

		SSL_CTX_set_verify(self->ctx, mode, gsi_wrapper_global_verify_callback);
	}
	else
		SSL_CTX_set_verify(self->ctx, mode, global_verify_callback);

	Py_RETURN_NONE;
}

static char
		ssl_Context_set_GSI_verify_doc[] =
				"\n\
		Set GSI verification callback\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_GSI_verify( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":set_GSI_verify") )
		return NULL;

	//SSL_CTX_set_cert_verify_callback( self->ctx, ssl_callback_GSI_verify, 0 );
	Py_RETURN_NONE;
}

static char
		ssl_Context_set_verify_depth_doc[] =
				"\n\
		Set the verify depth\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		depth - An integer specifying the verify depth\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_verify_depth( ssl_ContextObj * self, PyObject * args )
{
	int depth;

	if ( !PyArg_ParseTuple(args, "i:set_verify_depth", &depth) )
		return NULL;

	SSL_CTX_set_verify_depth(self->ctx, depth);
	Py_RETURN_NONE;
}

static char
		ssl_Context_get_verify_mode_doc[] =
				"\n\
		Get the verify mode\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   The verify mode\n\
		";

static PyObject *
ssl_Context_get_verify_mode( ssl_ContextObj * self, PyObject * args )
{
	int mode;

	if ( !PyArg_ParseTuple(args, ":get_verify_mode") )
		return NULL;

	mode = SSL_CTX_get_verify_mode(self->ctx);
	return PyInt_FromLong((long) mode);
}

static char
		ssl_Context_get_verify_depth_doc[] =
				"\n\
		Get the verify depth\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   The verify depth\n\
		";

static PyObject *
ssl_Context_get_verify_depth( ssl_ContextObj * self, PyObject * args )
{
	int depth;

	if ( !PyArg_ParseTuple(args, ":get_verify_depth") )
		return NULL;

	depth = SSL_CTX_get_verify_depth(self->ctx);
	return PyInt_FromLong((long) depth);
}

static char
		ssl_Context_load_tmp_dh_doc[] =
				"\n\
		Load parameters for Ephemeral Diffie-Hellman\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		dhfile - The file to load EDH parameters from\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_load_tmp_dh( ssl_ContextObj * self, PyObject * args )
{
	char *dhfile;

	BIO *bio;

	DH *dh;

	if ( !PyArg_ParseTuple(args, "s:load_tmp_dh", &dhfile) )
		return NULL;

	bio = BIO_new_file(dhfile, "r");
	if ( bio == NULL )
		return PyErr_NoMemory();

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	SSL_CTX_set_tmp_dh(self->ctx, dh);
	DH_free(dh);
	BIO_free(bio);

	Py_RETURN_NONE;
}

static char
		ssl_Context_set_cipher_list_doc[] =
				"\n\
		Change the cipher list\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		cipher_list - A cipher list, see ciphers(1)\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_cipher_list( ssl_ContextObj * self, PyObject * args )
{
	char *cipher_list;

	if ( !PyArg_ParseTuple(args, "s:set_cipher_list", &cipher_list) )
		return NULL;

	if ( !SSL_CTX_set_cipher_list(self->ctx, cipher_list) )
	{
		exception_from_error_queue();
		return NULL;
	}
	else
	{
		Py_RETURN_NONE;
	}
}

static char
		ssl_Context_set_timeout_doc[] =
				"\n\
		Set session timeout\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		t - The timeout in seconds\n\
		Returns:   The previous session timeout\n\
		";

static PyObject *
ssl_Context_set_timeout( ssl_ContextObj * self, PyObject * args )
{
	long t, ret;

	if ( !PyArg_ParseTuple(args, "l:set_timeout", &t) )
		return NULL;

	ret = SSL_CTX_set_timeout(self->ctx, t);
	return PyLong_FromLong(ret);
}

static char
		ssl_Context_get_timeout_doc[] =
				"\n\
		Get the session timeout\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   The session timeout\n\
		";

static PyObject *
ssl_Context_get_timeout( ssl_ContextObj * self, PyObject * args )
{
	long ret;

	if ( !PyArg_ParseTuple(args, ":get_timeout") )
		return NULL;

	ret = SSL_CTX_get_timeout(self->ctx);
	return PyLong_FromLong(ret);
}

static char
		ssl_Context_set_info_callback_doc[] =
				"\n\
		Set the info callback\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		callback - The Python callback to use\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_info_callback( ssl_ContextObj * self, PyObject * args )
{
	PyObject *callback,*old;

	if ( !PyArg_ParseTuple(args, "O:set_info_callback", &callback) )
		return NULL;

	if ( !PyCallable_Check(callback) )
	{
		PyErr_SetString(PyExc_TypeError, "expected PyCallable");
		return NULL;
	}

	old = self->info_callback;
	Py_INCREF(callback);
	self->info_callback = callback;
	Py_DECREF( old );
	SSL_CTX_set_info_callback(self->ctx, global_info_callback);

	Py_RETURN_NONE;
}

static char
		ssl_Context_get_app_data_doc[] =
				"\n\
		Get the application data (supplied via set_app_data())\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   The application data\n\
		";

static PyObject *
ssl_Context_get_app_data( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":get_app_data") )
		return NULL;

	Py_INCREF(self->app_data);
	return self->app_data;
}

static char
		ssl_Context_set_app_data_doc[] =
				"\n\
		Set the application data (will be returned from get_app_data())\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		data - Any Python object\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_app_data( ssl_ContextObj * self, PyObject * args )
{
	PyObject *data,*old;

	if ( !PyArg_ParseTuple(args, "O:set_app_data", &data) )
		return NULL;

	old=self->app_data;
	Py_INCREF( data );
	self->app_data = data;
	Py_DECREF( old );

	Py_RETURN_NONE;
}

static char
		ssl_Context_set_cert_store_doc[] =
				"\n\
		Set the certificate store for the context\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be an X509 cert store\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_set_cert_store( ssl_ContextObj * self, PyObject * args )
{
	static PyTypeObject *crypto_X509StoreObj_Type = NULL;
	crypto_X509StoreObj *pyStore;

	if ( !PyArg_ParseTuple(args, "O:set_cert_store", &pyStore) )
		return NULL;

	if ( !crypto_X509StoreObj_Type )
	{
		if ( strcmp(pyStore->ob_type->tp_name, "X509Store") != 0
				|| pyStore->ob_type->tp_basicsize != sizeof(crypto_X509StoreObj) )
		{
			PyErr_SetString(PyExc_TypeError, "Expected an X509Store object");
			return NULL;
		}

		crypto_X509StoreObj_Type = pyStore->ob_type;
	}
	else if ( pyStore->ob_type != crypto_X509StoreObj_Type )
	{
		PyErr_SetString(PyExc_TypeError, "Expected a X509Store object");
		return NULL;
	}

	SSL_CTX_set_cert_store(self->ctx, pyStore->x509_store);
	pyStore->dealloc = 0;

	Py_RETURN_NONE;
}

static char
		ssl_Context_get_cert_store_doc[] =
				"\n\
		Get the certificate store for the context\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   A X509Store object\n\
		";

static PyObject *
ssl_Context_get_cert_store( ssl_ContextObj * self, PyObject * args )
{
	X509_STORE *store;

	if ( !PyArg_ParseTuple(args, ":get_cert_store") )
		return NULL;

	if ( (store = SSL_CTX_get_cert_store(self->ctx)) == NULL )
	{
		Py_RETURN_NONE;
	}
	else
	{
		return (PyObject *) crypto_X509Store_New(store, 0);
	}
}

static char
		ssl_Context_set_read_ahead_doc[] =
				"\n\
		Set read ahead\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		options - 1/0\n\
		Returns:   The new option bitmask.\n\
		";

static PyObject *
ssl_Context_set_read_ahead( ssl_ContextObj * self, PyObject * args )
{
	int ra;

	if ( !PyArg_ParseTuple(args, "l:set_read_ahead", &ra) )
		return NULL;

	SSL_CTX_set_read_ahead( self->ctx, ra );

	Py_RETURN_NONE;
}

static char
		ssl_Context_set_options_doc[] =
				"\n\
		Add options. Options set before are not cleared!\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		options - The options to add.\n\
		Returns:   The new option bitmask.\n\
		";

static PyObject *
ssl_Context_set_options( ssl_ContextObj * self, PyObject * args )
{
	long options;

	if ( !PyArg_ParseTuple(args, "l:set_options", &options) )
		return NULL;

	return PyInt_FromLong(SSL_CTX_set_options(self->ctx, options));
}

static char
		ssl_Context_add_session_doc[] =
				"\n\
		Add session to context cache.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		session - The session to add.\n\
		Returns:   None\n\
		";

static PyObject *
ssl_Context_add_session( ssl_ContextObj * self, PyObject * args )
{
	ssl_SessionObj *session;

	if ( !PyArg_ParseTuple(args, "O!:set_options", &ssl_Session_Type, &session) )
		return NULL;

	if ( session->session )
		SSL_CTX_add_session(self->ctx, session->session);

	Py_RETURN_NONE;
}

static char
		ssl_Context_get_session_stats_doc[] =
				"\n\
		Get session statistics from context.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   A dictionary containing sessions stats.\n\
		";

static PyObject *
ssl_Context_get_session_stats( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":set_session_stats") )
		return NULL;

	return Py_BuildValue("{s:i,s:i,s:i,s:i}", "hits", SSL_CTX_sess_hits(
			self->ctx), "misses", SSL_CTX_sess_misses(self->ctx),
			"cached sessions", SSL_CTX_sess_number(self->ctx), "cache size",
			SSL_CTX_sess_get_cache_size(self->ctx));
}

static char
		ssl_Context_set_session_timeout_doc[] =
				"\n\
		Modify session timeout for context. Newer sessions will use the new timeout.\n\
		For previous ones timeout is preserved.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		timeout - New timeout to set.\n\
		Returns:   None.\n\
		";

static PyObject *
ssl_Context_set_session_timeout( ssl_ContextObj * self, PyObject * args )
{
	long timeout;

	if ( !PyArg_ParseTuple(args, "l:set_session_timeout", &timeout) )
		return NULL;

	SSL_CTX_set_timeout(self->ctx, timeout);

	Py_RETURN_NONE;

}

static char
		ssl_Context_flush_sessions_doc[] =
				"\n\
		Flush sessions.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   None.\n\
		";

static PyObject *
ssl_Context_flush_sessions( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":flush_sessions") )
		return NULL;

	SSL_CTX_flush_sessions(self->ctx, time(0));

	Py_RETURN_NONE;
}

static char
		ssl_Context_get_session_timeout_doc[] =
				"\n\
		Get session timeout.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		options - The options to add.\n\
		Returns:   The timeout.\n\
		";

static PyObject *
ssl_Context_get_session_timeout( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":get_session_timeout") )
		return NULL;

	return PyInt_FromLong(SSL_CTX_get_timeout(self->ctx));

}

static char
		ssl_Context_set_session_cache_mode_doc[] =
				"\n\
		Set the context session cache mode.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be:\n\
		mode - Mode to setup.\n\
		Returns:   The timeout.\n\
		";

static PyObject *
ssl_Context_set_session_cache_mode( ssl_ContextObj * self, PyObject * args )
{
	long mode;

	if ( !PyArg_ParseTuple(args, "l:set_session_cache_mode", &mode) )
		return NULL;

	SSL_CTX_set_session_cache_mode(self->ctx, mode);

	Py_RETURN_NONE;
}

static char
		ssl_Context_get_session_cache_mode_doc[] =
				"\n\
		Get the context session cache mode.\n\
		\n\
		Arguments: self - The Context object\n\
		args - The Python argument tuple, should be empty\n\
		Returns:   The timeout.\n\
		";

static PyObject *
ssl_Context_get_session_cache_mode( ssl_ContextObj * self, PyObject * args )
{
	if ( !PyArg_ParseTuple(args, ":get_session_cache_mode") )
		return NULL;

	return PyLong_FromLong(SSL_CTX_get_session_cache_mode(self->ctx));

}

/*
 * Member methods in the Context object
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)ssl_Context_name, METH_VARARGS }
 * for convenience
 * ADD_ALIAS(name,real) creates an "alias" of the ssl_Context_real
 * function with the name 'name'
 */
#define ADD_METHOD(name) { #name, (PyCFunction)ssl_Context_##name, METH_VARARGS, ssl_Context_##name##_doc }
static PyMethodDef ssl_Context_methods[] =
{
ADD_METHOD( load_verify_locations ),
ADD_METHOD( load_verify_locations_path ),
ADD_METHOD( set_passwd_cb ),
ADD_METHOD( use_certificate_chain_file ),
ADD_METHOD( use_certificate_file ),
ADD_METHOD( use_certificate_chain ),
ADD_METHOD( use_certificate_chain_string ),
ADD_METHOD( use_certificate ),
ADD_METHOD( use_privatekey_string ),
ADD_METHOD( use_privatekey_file ),
ADD_METHOD( use_privatekey ),
ADD_METHOD( check_privatekey ),
ADD_METHOD( load_client_ca ),
ADD_METHOD( set_session_id ),
ADD_METHOD( set_verify ),
ADD_METHOD( set_GSI_verify ),
ADD_METHOD( set_verify_depth ),
ADD_METHOD( get_verify_mode ),
ADD_METHOD( get_verify_depth ),
ADD_METHOD( load_tmp_dh ),
ADD_METHOD( set_cipher_list ),
ADD_METHOD( set_timeout ),
ADD_METHOD( get_timeout ),
ADD_METHOD( set_info_callback ),
ADD_METHOD( get_app_data ),
ADD_METHOD( set_app_data ),
ADD_METHOD( set_cert_store ),
ADD_METHOD( get_cert_store ),
ADD_METHOD( set_options ),
ADD_METHOD( set_read_ahead ),
ADD_METHOD( add_session ),
ADD_METHOD( get_session_stats ),
ADD_METHOD( set_session_timeout ),
ADD_METHOD( get_session_timeout ),
ADD_METHOD( flush_sessions ),
ADD_METHOD( set_session_cache_mode ),
ADD_METHOD( get_session_cache_mode ),
{ NULL, NULL } };

#undef ADD_METHOD

/* Constructor, takes an int specifying which method to use */

/*
 * Constructor for Context objects
 *
 * Arguments: i_method - The SSL method to use, one of the
 *                       SSLv3_METHOD, SSLv23_METHOD and TLSv1_METHOD
 *                       constants.
 * Returns:   The newly created Context object
 */

ssl_ContextObj *
ssl_Context_New( int i_method )
{
	const SSL_METHOD *method;

	ssl_ContextObj *self;

	char clientMethod = 0;

	switch ( i_method )
	{
		/* Too bad TLSv1 servers can't accept SSLv3 clients */
		case ssl_SSLv23_METHOD:
			method = SSLv23_method();
			break;
		case ssl_SSLv23_CLIENT_METHOD:
			method = SSLv23_client_method();
			clientMethod = 1;
			break;
		case ssl_SSLv23_SERVER_METHOD:
			method = SSLv23_server_method();
			break;
		case ssl_SSLv3_METHOD:
			method = SSLv3_method();
			break;
		case ssl_SSLv3_CLIENT_METHOD:
			method = SSLv3_client_method();
			clientMethod = 1;
			break;
		case ssl_SSLv3_SERVER_METHOD:
			method = SSLv3_server_method();
			break;
		case ssl_TLSv1_METHOD:
			method = TLSv1_method();
			break;
		case ssl_TLSv1_CLIENT_METHOD:
			method = TLSv1_client_method();
			clientMethod = 1;
			break;
		case ssl_TLSv1_SERVER_METHOD:
			method = TLSv1_server_method();
			break;
		case ssl_TLSv1_1_METHOD:
			method = TLSv1_1_method();
			break;
		case ssl_TLSv1_1_CLIENT_METHOD:
			method = TLSv1_1_client_method();
			clientMethod = 1;
			break;
		case ssl_TLSv1_1_SERVER_METHOD:
			method = TLSv1_1_server_method();
			break;
		case ssl_TLSv1_2_METHOD:
			method = TLSv1_2_method();
			break;
		case ssl_TLSv1_2_CLIENT_METHOD:
			method = TLSv1_2_client_method();
			clientMethod = 1;
			break;
		case ssl_TLSv1_2_SERVER_METHOD:
			method = TLSv1_2_server_method();
			break;
		default:
			PyErr_SetString(PyExc_ValueError, "No such protocol");
			return NULL;
	}

	self = PyObject_GC_New(ssl_ContextObj, &ssl_Context_Type);
	if ( self == NULL )
		return (ssl_ContextObj *) PyErr_NoMemory();

	self->clientMethod = clientMethod;

	self->ctx = SSL_CTX_new(method);
	Py_INCREF(Py_None);
	self->passphrase_callback = Py_None;
	Py_INCREF(Py_None);
	self->verify_callback = Py_None;
	Py_INCREF(Py_None);
	self->info_callback = Py_None;

	Py_INCREF(Py_None);
	self->passphrase_userdata = Py_None;

	Py_INCREF(Py_None);
	self->app_data = Py_None;

	/* Some initialization that's required to operate smoothly in Python */
	SSL_CTX_set_app_data(self->ctx, self);
	SSL_CTX_set_mode(self->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE
			| SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);

	self->tstate = NULL;
	PyObject_GC_Track((PyObject *) self);

	return self;
}

/*
 * Find attribute
 *
 * Arguments: self - The Context object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
ssl_Context_getattr( ssl_ContextObj * self, char *name )
{
	return Py_FindMethod(ssl_Context_methods, (PyObject *) self, name);
}

/*
 * Call the visitproc on all contained objects.
 *
 * Arguments: self - The Context object
 *            visit - Function to call
 *            arg - Extra argument to visit
 * Returns:   0 if all goes well, otherwise the return code from the first
 *            call that gave non-zero result.
 */
static int ssl_Context_traverse( ssl_ContextObj * self, visitproc visit,
		void *arg )
{
	Py_VISIT(self->passphrase_callback);
	Py_VISIT(self->passphrase_userdata);
	Py_VISIT(self->verify_callback);
	Py_VISIT(self->info_callback);
	Py_VISIT(self->app_data);
	return 0;
}

/*
 * Decref all contained objects and zero the pointers.
 *
 * Arguments: self - The Context object
 * Returns:   Always 0.
 */
static int ssl_Context_clear( ssl_ContextObj * self )
{
	Py_CLEAR(self->passphrase_callback);
	Py_CLEAR(self->passphrase_userdata);
	Py_CLEAR(self->verify_callback);
	Py_CLEAR(self->info_callback);
	Py_CLEAR(self->app_data);
	return 0;
}

/*
 * Deallocate the memory used by the Context object
 *
 * Arguments: self - The Context object
 * Returns:   None
 */
static void ssl_Context_dealloc( ssl_ContextObj * self )
{
	PyObject_GC_UnTrack((PyObject *) self);

	SSL_CTX_free(self->ctx);

	ssl_Context_clear(self);

	PyObject_GC_Del(self);
}

PyTypeObject ssl_Context_Type
=
{
	PyObject_HEAD_INIT( NULL ) 0,
	"Context",
	sizeof( ssl_ContextObj ),
	0,
	( destructor ) ssl_Context_dealloc,
	NULL, /* print */
	( getattrfunc ) ssl_Context_getattr,
	NULL, /* setattr */
	NULL, /* compare */
	NULL, /* repr */
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
	( traverseproc ) ssl_Context_traverse,
	( inquiry ) ssl_Context_clear,
};

/*
 * Initialize the Context part of the SSL sub module
 *
 * Arguments: dict - Dictionary of the OpenSSL.SSL module
 * Returns:   1 for success, 0 otherwise
 */
int init_ssl_context( PyObject * dict )
{
	ssl_Context_Type.ob_type = &PyType_Type;
	Py_INCREF(&ssl_Context_Type);
	if ( PyDict_SetItemString(dict, "ContextType",
			(PyObject *) &ssl_Context_Type) != 0 )
		return 0;

	return 1;
}
