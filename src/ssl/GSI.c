/****************************************************************************\
* ssl_callback_GSI_verify and GSI_name_issuer_check are written by           *
* Mike Jones,                                                                *
* SVE, Manchester Computing,                                                 *
* The University of Manchester.                                              *
* It is based heavily on X509_verify_cert and accompanying routines          *
* taken directly from Openssl                                                *
******************************************************************************
* COPYRIGHT UNIVERSITY OF MANCHESTER, 2003/4                                 *
*                                                                            *
* Author: Michael A S Jones                                                  *
* mike.jones@man.ac.uk                                                       *
*                                                                            *
* LICENCE TERMS                                                              *
*                                                                            *
* Redistribution and use in source and binary forms, with or without         *
* modification, are permitted provided that the following conditions         *
* are met:                                                                   *
*  1. Redistributions of source code must retain the above copyright         *
*     notice, this list of conditions and the following disclaimer.          *
*  2. Redistributions in binary form must reproduce the above copyright      *
*     notice, this list of conditions and the following disclaimer in the    *
*     documentation and/or other materials provided with the distribution.   *
*                                                                            *
* THIS MATERIAL IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"*
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE  *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE *
* ARE DISCLAIMED. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE   *
* PROGRAM IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE   *
* COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.                     *
\****************************************************************************/
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "ssl.h"

static int null_callback( int ok, X509_STORE_CTX * e )
{
	return ok;
};


static int internal_verify( X509_STORE_CTX * ctx )
{
	int i, ok = 0, n;
	X509 *xs, *xi;
	EVP_PKEY *pkey = NULL;
	time_t *ptime;
	int ( *cb ) (  );

	cb = ctx->verify_cb;
	if ( cb == NULL )
		cb = null_callback;

	n = sk_X509_num( ctx->chain );
	ctx->error_depth = n - 1;
	n--;
	xi = sk_X509_value( ctx->chain, n );
	if ( ctx->flags & X509_V_FLAG_USE_CHECK_TIME )
		ptime = &ctx->check_time;
	else
		ptime = NULL;
	if ( ctx->check_issued( ctx, xi, xi ) )
		xs = xi;
	else
	{
		if ( n <= 0 )
		{
			ctx->error = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
			ctx->current_cert = xi;
			ok = cb( 0, ctx );
			goto end;
		}
		else
		{
			n--;
			ctx->error_depth = n;
			xs = sk_X509_value( ctx->chain, n );
		}
	}

/*	ctx->error=0;  not needed */
	while ( n >= 0 )
	{
		ctx->error_depth = n;
		if ( !xs->valid )
		{
			if ( ( pkey = X509_get_pubkey( xi ) ) == NULL )
			{
				ctx->error = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
				ctx->current_cert = xi;
				ok = ( *cb ) ( 0, ctx );
				if ( !ok )
					goto end;
			}
			if ( X509_verify( xs, pkey ) <= 0 )
			{
				ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
				ctx->current_cert = xs;
				ok = ( *cb ) ( 0, ctx );
				if ( !ok )
				{
					EVP_PKEY_free( pkey );
					goto end;
				}
			}
			EVP_PKEY_free( pkey );
			pkey = NULL;

			i = X509_cmp_time( X509_get_notBefore( xs ), ptime );
			if ( i == 0 )
			{
				ctx->error = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
				ctx->current_cert = xs;
				ok = ( *cb ) ( 0, ctx );
				if ( !ok )
					goto end;
			}
			if ( i > 0 )
			{
				ctx->error = X509_V_ERR_CERT_NOT_YET_VALID;
				ctx->current_cert = xs;
				ok = ( *cb ) ( 0, ctx );
				if ( !ok )
					goto end;
			}
			xs->valid = 1;
		}

		i = X509_cmp_time( X509_get_notAfter( xs ), ptime );
		if ( i == 0 )
		{
			ctx->error = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
			ctx->current_cert = xs;
			ok = ( *cb ) ( 0, ctx );
			if ( !ok )
				goto end;
		}

		if ( i < 0 )
		{
			ctx->error = X509_V_ERR_CERT_HAS_EXPIRED;
			ctx->current_cert = xs;
			ok = ( *cb ) ( 0, ctx );
			if ( !ok )
				goto end;
		}

		/* CRL CHECK */

		/* The last error (if any) is still in the error value */
		ctx->current_cert = xs;
		ok = ( *cb ) ( 1, ctx );
		if ( !ok )
			goto end;

		n--;
		if ( n >= 0 )
		{
			xi = xs;
			xs = sk_X509_value( ctx->chain, n );
		}
	}
	ok = 1;
  end:
	return ok;
};


int GSI_name_issuer_check( char *iname, char *sname )
{
	int ilen, slen;
	char *pp;

	/* Load Certificate (i in chain) subject and Issuer */
	/* cp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0); cp2 = 
	   X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0); */
	ilen = strlen( iname );
	slen = strlen( sname );

	/* If issuer did not have relevant signing purpose */
	if ( ilen > slen )
		return 1;				/* User cannot sign shortened DN. */
	if ( strncmp( sname, iname, ilen ) )
		return 2;				/* Subject must begin with issuer. */
	pp = sname + ilen;			/* Set pointer to end of dn base. */
	/* Remander of Subject must be either "/CN=proxy" or "/CN=limited
	   proxy". */
	if ( strstr( iname, "/CN=limited proxy" ) )
	{
		if ( strcmp( pp, "/CN=limited proxy" ) )
			return 3;			/* limited proxy must propagate
								   limitedness */
	}
	else
	{
		if ( strcmp( pp, "/CN=proxy" )
			 && strcmp( pp, "/CN=limited proxy" ) )
			return 4;
	}
	return 0;
}

int ssl_callback_GSI_verify( X509_STORE_CTX * ctx, void *dummy )
{
	X509 *x, *xtmp, *chain_ss = NULL;
	X509_NAME *xn;
	int depth, i, ok = 0;
	int num;
	int ( *cb ) (  );

	STACK_OF( X509 ) * sktmp = NULL;
	char *childcertname;
	X509 *cert, *issuer;
	int j;
	int ret;

	if ( ctx->cert == NULL )
	{
		X509err( X509_F_X509_VERIFY_CERT,
				 X509_R_NO_CERT_SET_FOR_US_TO_VERIFY );
		return -1;
	}

	cb = ctx->verify_cb;
	if ( cb == NULL )
		cb = null_callback;

	/* first we make sure the chain we are going to build is present and
	   that the first entry is in place */
	if ( ctx->chain == NULL )
	{
		if ( ( ( ctx->chain = sk_X509_new_null(  ) ) == NULL )
			 || ( !sk_X509_push( ctx->chain, ctx->cert ) ) )
		{
			X509err( X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE );
			goto end;
		}
		CRYPTO_add( &ctx->cert->references, 1, CRYPTO_LOCK_X509 );
		ctx->last_untrusted = 1;
	}

	/* We use a temporary STACK so we can chop and hack at it */
	if ( ctx->untrusted != NULL
		 && ( sktmp = sk_X509_dup( ctx->untrusted ) ) == NULL )
	{
		X509err( X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE );
		goto end;
	}

	/* set it */
	num = sk_X509_num( ctx->chain );
	x = sk_X509_value( ctx->chain, num - 1 );
	depth = ctx->depth;

	/* fill it */
	for ( ;; )
	{
		/* If we have enough, we break */
		if ( depth < num )
			break;

		/* If we are self signed, we break */
		xn = X509_get_issuer_name( x );

		if ( ctx->check_issued( ctx, x, x ) )
			break;

		/* If we were passed a cert chain, use it first */
		if ( ctx->untrusted != NULL )
		{
			/* Inline find_issuer xtmp=find_issuer(ctx, sktmp,x); */
			for ( j = 0; j < sk_X509_num( sktmp ); j++ )
			{
				issuer = sk_X509_value( sktmp, j );

				/* Inline check_issued */

				ret = X509_check_issued( issuer, x );

				if ( ret == X509_V_OK )
				{
					xtmp = issuer;
					break;
				}
				/* check if no_certsign that this is a valid GSI proxy by
				   name convension (fortunatly no_certsign is last check
				   in X509_check_issued) */
				else if ( ret == X509_V_ERR_KEYUSAGE_NO_CERTSIGN
						  &&
						  !GSI_name_issuer_check( X509_NAME_oneline
												  ( X509_get_subject_name
													( issuer ), NULL, 0 ),
												  X509_NAME_oneline
												  ( X509_get_subject_name
													( x ), NULL, 0 ) ) )
				{
					xtmp = issuer;
					break;
				}
				/* If we haven't asked for issuer errors don't set ctx */
				else if ( !( ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK ) )
				{
					xtmp = NULL;
				}
				else
				{
					ctx->error = ret;
					ctx->current_cert = x;
					ctx->current_issuer = issuer;
					if ( ctx->verify_cb )
						xtmp = ctx->verify_cb( 0, ctx );
					else
						xtmp = 0;
				}
				/* End of check_issued */
			}
			/* End of find_issuer */

			if ( xtmp != NULL )
			{
				if ( !sk_X509_push( ctx->chain, xtmp ) )
				{
					X509err( X509_F_X509_VERIFY_CERT,
							 ERR_R_MALLOC_FAILURE );
					goto end;
				}
				CRYPTO_add( &xtmp->references, 1, CRYPTO_LOCK_X509 );
				sk_X509_delete_ptr( sktmp, xtmp );
				ctx->last_untrusted++;
				x = xtmp;
				num++;
				/* reparse the full chain for the next one */
				continue;
			}
		}
		break;
	}

	/* at this point, chain should contain a list of untrusted
	   certificates.  We now need to add at least one trusted one, if
	   possible, otherwise we complain. */

	/* Examine last certificate in chain and see if it is self signed. */
	i = sk_X509_num( ctx->chain );
	x = sk_X509_value( ctx->chain, i - 1 );
	xn = X509_get_subject_name( x );

	if ( ctx->check_issued( ctx, x, x ) )
	{
		/* we have a self signed certificate */
		if ( sk_X509_num( ctx->chain ) == 1 )
		{
			/* We have a single self signed certificate: see if we can
			   find it in the store. We must have an exact match to avoid
			   possible impersonation. */
			ok = ctx->get_issuer( &xtmp, ctx, x );
			if ( ( ok <= 0 ) || X509_cmp( x, xtmp ) )
			{
				ctx->error = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
				ctx->current_cert = x;
				ctx->error_depth = i - 1;
				if ( ok == 1 )
					X509_free( xtmp );
				ok = cb( 0, ctx );
				if ( !ok )
					goto end;
			}
			else
			{
				/* We have a match: replace certificate with store version
				   so we get any trust settings. */
				X509_free( x );
				x = xtmp;
				sk_X509_set( ctx->chain, i - 1, x );
				ctx->last_untrusted = 0;
			}
		}
		else
		{
			/* extract and save self signed certificate for later use */
			chain_ss = sk_X509_pop( ctx->chain );
			ctx->last_untrusted--;
			num--;
			x = sk_X509_value( ctx->chain, num - 1 );
		}
	}

	/* We now lookup certs from the certificate store */
	for ( ;; )
	{
		/* If we have enough, we break */
		if ( depth < num )
			break;

		/* If we are self signed, we break */
		xn = X509_get_issuer_name( x );
		if ( ctx->check_issued( ctx, x, x ) )
			break;

		ok = ctx->get_issuer( &xtmp, ctx, x );


		if ( ok < 0 )
			return ok;
		if ( ok == 0 )
			break;

		x = xtmp;
		if ( !sk_X509_push( ctx->chain, x ) )
		{
			X509_free( xtmp );
			X509err( X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE );
			return 0;
		}
		num++;
	}

	/* we now have our chain, lets check it... */
	xn = X509_get_issuer_name( x );

	/* Is last certificate looked up self signed? */
	if ( !ctx->check_issued( ctx, x, x ) )
	{
		if ( ( chain_ss == NULL )
			 || !ctx->check_issued( ctx, x, chain_ss ) )
		{
			if ( ctx->last_untrusted >= num )
				ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
			else
				ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
			ctx->current_cert = x;
		}
		else
		{
			sk_X509_push( ctx->chain, chain_ss );
			num++;
			ctx->last_untrusted = num;
			ctx->current_cert = chain_ss;
			ctx->error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
			chain_ss = NULL;
		}
		ctx->error_depth = num - 1;
		ok = cb( 0, ctx );
		if ( !ok )
			goto end;
	}

	/* We have the chain complete: now we need to check its purpose */
	if ( ctx->purpose > 0 )
	{
		/* Inline check_chain_purpose */
		cb = ctx->verify_cb;
		if ( cb == NULL )
			cb = null_callback;
		/* Check all untrusted certificates */
		for ( j = 0; j < ctx->last_untrusted; j++ )
		{
			cert = sk_X509_value( ctx->chain, j );
			if ( j > 0 )
				childcertname =
					X509_NAME_oneline( X509_get_subject_name
									   ( sk_X509_value
										 ( ctx->chain, ( j - 1 ) ) ), NULL,
									   0 );
			else
				childcertname = NULL;

			if ( !X509_check_purpose( cert, ctx->purpose, j ) )
			{
				if ( j
					 &&
					 !GSI_name_issuer_check( X509_NAME_oneline
											 ( X509_get_subject_name
											   ( cert ), NULL, 0 ),
											 childcertname ) )
				{				/* Not client cert and bad CA purpose then 
								   need to check signed childcert is GSI
								   compatible with this cert */
					ok = 1;
				}
				else
				{
					if ( j )
						ctx->error = X509_V_ERR_INVALID_CA;
					else
						ctx->error = X509_V_ERR_INVALID_PURPOSE;
					ctx->error_depth = j;
					ctx->current_cert = cert;
					ok = cb( 0, ctx );
					if ( !ok )
						goto end;
				}
			}
			/* Check pathlen */
			if ( ( j > 1 ) && ( cert->ex_pathlen != -1 )
				 && ( j > ( cert->ex_pathlen + 1 ) ) )
			{
				ctx->error = X509_V_ERR_PATH_LENGTH_EXCEEDED;
				ctx->error_depth = j;
				ctx->current_cert = cert;
				ok = cb( 0, ctx );
				if ( !ok )
					goto end;
			}
		}
		ok = 1;
	}

	if ( !ok )
		goto end;
	/* The chain extensions are OK: check trust */

	if ( ctx->trust > 0 )
	{							/* Inline check_trust */
		cb = ctx->verify_cb;
		if ( cb == NULL )
			cb = null_callback;
		/* For now just check the last certificate in the chain */
		j = sk_X509_num( ctx->chain ) - 1;
		cert = sk_X509_value( ctx->chain, j );
		ok = X509_check_trust( cert, ctx->trust, 0 );
		if ( ok == X509_TRUST_TRUSTED )
			ok = 1;
		else
		{
			ctx->error_depth = sk_X509_num( ctx->chain ) - 1;
			ctx->current_cert = cert;
			if ( ok == X509_TRUST_REJECTED )
				ctx->error = X509_V_ERR_CERT_REJECTED;
			else
				ctx->error = X509_V_ERR_CERT_UNTRUSTED;
			ok = cb( 0, ctx );
		}
	}

	if ( !ok )
		goto end;

	/* We may as well copy down any DSA parameters that are required */
	X509_get_pubkey_parameters( NULL, ctx->chain );

	/* At this point, we have a chain and just need to verify it */
	ok = internal_verify( ctx );

	if ( 0 )
	{
	  end:
		X509_get_pubkey_parameters( NULL, ctx->chain );
	}
	if ( sktmp != NULL )
		sk_X509_free( sktmp );
	if ( chain_ss != NULL )
		X509_free( chain_ss );
	if ( ctx->error )
		return 0;
	else
		return 1;
};
