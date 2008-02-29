#include "ssl.h"

#define MIN_LOG_LEVEL 0

static void logMsg(int level, char *fmt, ...)
{
   char *mesg;
   va_list ap;

   va_start(ap, fmt);
   vasprintf(&mesg, fmt, ap);
   va_end(ap);

   if( level >= MIN_LOG_LEVEL )
    printf( "[%d] %s\n", level, mesg );

   free(mesg);
}

/* Later OpenSSL versions add a second pointer ... */
int gsiVerifyCertWrapper(X509_STORE_CTX *ctx, void *p)

/* Earlier ones have a single argument ... */
// int GRST_verify_cert_wrapper(X509_STORE_CTX *ctx)

/* Before 0.9.7 we cannot change the check_issued callback directly in
   the X509_STORE, so we must insert it in another callback that gets
   called early enough */
{
   ctx->check_issued = gsiX509CheckIssuedWrapper;

   return X509_verify_cert(ctx);
}

int gsiX509CheckIssuedWrapper(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
/* We change the default callback to use our wrapper and discard errors
   due to GSI proxy chains (ie where users certs act as CAs) */
{
   int ret;
   char *dummy;

   logMsg( 1, "Wrapper called" );
   dummy = X509_NAME_oneline( X509_get_subject_name(x), NULL, 0 );
   logMsg( 0, " Subject [%s]", dummy );
   if(dummy) OPENSSL_free(dummy);
   dummy = X509_NAME_oneline( X509_get_issuer_name(issuer), NULL, 0 );
   logMsg( 0, " Issuer [%s]", dummy );
   if(dummy) OPENSSL_free(dummy);



   ret = X509_check_issued(issuer, x);
   if (ret == X509_V_OK) return 1;

   /* Non self-signed certs without signing are ok if they passed
     the other checks inside X509_check_issued. Is this enough? */
   if ( ( ret == X509_V_ERR_KEYUSAGE_NO_CERTSIGN ) &&
        ( X509_NAME_cmp(X509_get_subject_name(issuer),
                        X509_get_subject_name(x)
                       ) != 0 ) ) return 1;

 /* If we haven't asked for issuer errors don't set ctx */
#if OPENSSL_VERSION_NUMBER < 0x00908000
   if (!(ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#else
   if (!(ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#endif

   ctx->error = ret;
   ctx->current_cert = x;
   ctx->current_issuer = issuer;
   return ctx->verify_cb(0, ctx);
}

int gsiVerifyCallback( int ok, X509_STORE_CTX *ctx )
{
//   SSL *ssl            = (SSL *) X509_STORE_CTX_get_app_data(ctx);
//   conn_rec *conn      = (conn_rec *) SSL_get_app_data(ssl);
//   server_rec *s       = conn->base_server;
//   SSLConnRec *sslconn =
//         (SSLConnRec *) ap_get_module_config(conn->conn_config, &ssl_module);
   int errnum          = X509_STORE_CTX_get_error(ctx);
   int errdepth        = X509_STORE_CTX_get_error_depth(ctx);
//   int first_non_ca;
   STACK_OF(X509) *certstack;
   //GRSTx509Chain *grst_chain;
   //SSL_CTX *context;
   char *dummy;
   X509 *cert;
   int rawOK = ok; //Is openssl telling us the cert is ok?

   logMsg( 0, "===============" );
   cert = X509_STORE_CTX_get_current_cert(ctx);
   dummy = X509_NAME_oneline( X509_get_subject_name(cert), NULL, 0 );
   logMsg( 0, "Subject [%s]", dummy );
   if(dummy) OPENSSL_free(dummy);
   dummy = X509_NAME_oneline( X509_get_issuer_name(cert), NULL, 0 );
   logMsg( 0, "Issuer [%s]", dummy );
   if(dummy) OPENSSL_free(dummy);

   //context = SSL_get_SSL_CTX(cert);

   /*
    * GSI Proxy user-cert-as-CA handling:
    * we skip Invalid CA errors at this stage, since we will check this
    * again at errdepth=0 for the full chain using GRSTx509ChainLoadCheck
    */
   logMsg( 0, "errnum %d INV_CA %d", errnum, X509_V_ERR_INVALID_CA);
   logMsg( 0, "errnum %d INVALID_PURPOSE %d", errnum, X509_V_ERR_INVALID_PURPOSE);
   if( errnum == X509_V_ERR_INVALID_CA || errnum == X509_V_ERR_INVALID_PURPOSE )
   {
      if( GRSTx509IsCA(cert) )
      {
         ok = TRUE;
         errnum = X509_V_OK;
         X509_STORE_CTX_set_error( ctx, errnum );
      }
   }

   /*
    * New style GSI Proxy handling, with critical ProxyCertInfo
    * extension: we use GRSTx509KnownCriticalExts() to check this
    */
   logMsg( 0, "errnum %d UNH_CRITICAL_EXT %d", errnum, X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION);
   if (errnum == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION )
   {
      if (GRSTx509KnownCriticalExts(X509_STORE_CTX_get_current_cert(ctx))
                                                              == GRST_RET_OK)
      {
         logMsg( 0, "GRSTx509KnownCriticalExts() accepts previously:  Unhandled Critical Extension (GSI Proxy?)" );

         ok = TRUE;
         errnum = X509_V_OK;
         X509_STORE_CTX_set_error(ctx, errnum);
      }
   }


   //ADRI:mod_ssl callback?
   //returned_ok = ssl_callback_SSLVerify(ok, ctx);
   /* in case ssl_callback_SSLVerify changed it */
   //errnum = X509_STORE_CTX_get_error(ctx);


   logMsg( 0, "OK %d Errdepth %d errnum %d == %d ", ok, errdepth, errnum, X509_V_OK );
   logMsg( 0, " errnum %d -> %s", errnum, X509_verify_cert_error_string(errnum) );

   if( errdepth == 0 && rawOK )
   /*
    * We've now got the last certificate - the identity being used for
    * this connection. At this point we check the whole chain for valid
    * CAs or, failing that, GSI-proxy validity using GRSTx509CheckChain.
    */
   {
      logMsg( 0, "Checking x509 chain" );
      certstack = (STACK_OF(X509) *) X509_STORE_CTX_get_chain(ctx);

      //errnum = GRSTx509ChainLoadCheck(&grst_chain, certstack, NULL,
      //                            "/home/adria/Devel/DIRAC3/etc/grid-security/certificates/" );
      //GRSTx509ChainFree(grst_chain);

      //errnum = grid_verifyProxy( certstack );
      errnum = gsiVerifyProxyChain( certstack );
      X509_STORE_CTX_set_error(ctx, errnum);

      if (errnum != X509_V_OK)
      {
         logMsg( 0, "Invalid certificate chain reported by gsiVerifyProxyChain()");

         ok = FALSE;
      }
      else
         logMsg( 0, "Valid certificate chain reported by gsiVerifyProxyChain()");

   }

   return ok;
}

/// Check critical extensions
int GRSTx509KnownCriticalExts(X509 *cert)
///
/// Returning GRST_RET_OK if all of extensions are known to us or
/// OpenSSL; GRST_REF_FAILED otherwise.
///
/// This function relies on functionality (X509_supported_extension)
/// introduced in 0.9.7.
{
   int  i;
   char s[80];
   X509_EXTENSION *ex;

   for (i = 0; i < X509_get_ext_count(cert); ++i)
   {
      ex = X509_get_ext(cert, i);

      if (X509_EXTENSION_get_critical(ex) &&
                           !X509_supported_extension(ex))
      {
         OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);

         if (strcmp(s, GRST_PROXYCERTINFO_OID) != 0) return GRST_RET_FAILED;
      }
   }

   return GRST_RET_OK;
}

//ADRI:Rocking version of the verification
unsigned long gsiVerifyProxyChain( STACK_OF(X509) *certstack )
{
   int depth = sk_X509_num( certstack ); //Number of certs in stack
   int prevWasCA = 1;                    //Initial cert is a CA
   int prevWasLimitedProxy = 0;          //Initial cert is not a limited proxy
   int i, issueCertCheck;
   int claimsCABehaviour;
   int lenSubject, lenIssuer;
   int foundError = 0;
   char *certDN;
   char *issuerDN;
   char *proxyDNchunk;
   X509 *prevCert, *cert;
   time_t now;

   //Set current time
   time(&now);

   //Get top level CA cert in stack
   prevCert = sk_X509_value( certstack, depth-1 );

   for( i = depth-2; i>=0; i-- )
   {
      logMsg( 1, "---" );
      cert = sk_X509_value( certstack, i );

      certDN = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0);
      issuerDN = X509_NAME_oneline( X509_get_issuer_name( cert ), NULL, 0);
      lenSubject = strlen( certDN );
      lenIssuer = strlen( issuerDN );

      logMsg( 1, "Checking subject [%s]", certDN );
      logMsg( 1, "Checking issuer  [%s]", issuerDN );

      //Checking the issuer has already been done by openSSL and the main wrapper

      claimsCABehaviour = GRSTx509IsCA( cert );

      //Is a normal CA cert
      if( !claimsCABehaviour )
      {
         //If previous wasn't a CA then error!
         if( !prevWasCA )
         {
            foundError |= X509_V_ERR_APPLICATION_VERIFICATION;
         }
         //Seems ok
         prevWasCA = 1;
      }
      //Can be either a user cert or a proxy
      else
      {
         //Has to be a user cert issued by a real CA
         if( prevWasCA )
         {
            prevWasCA = 0;
         }
         //Proxy!!!
         else
         {
            //We don't accept proxies of limited ones
            if( prevWasLimitedProxy )
            {
               foundError |= X509_V_ERR_APPLICATION_VERIFICATION;
            }
            /* User not allowed to sign shortened DN */
            else if( lenIssuer > lenSubject )
            {
               logMsg( 2, "It is not allowed to sign a shorthened DN.");
               foundError |= X509_V_ERR_INVALID_CA;
            }
            /* Proxy subject must begin with issuer. */
            else if( strncmp( certDN, issuerDN, lenIssuer ) != 0 )
            {
               logMsg( 2, "Proxy subject must begin with the issuer.");
               foundError |= X509_V_ERR_INVALID_CA;
            }
            else
            {
               /* Set pointer to end of base DN in cert_DN */
               proxyDNchunk = &certDN[lenIssuer];

               /* First attempt at support for Old and New style GSI
                  proxies: /CN=anything is ok for now */
               if( strncmp( proxyDNchunk, "/CN=", 4 ) != 0 )
               {
                  logMsg( 2, "Could not find a /CN= structure in the DN, thus it is not a proxy.");
                  foundError |= X509_V_ERR_INVALID_CA;
               }

               if( strncmp( proxyDNchunk, "/CN=limited proxy", 17 ) == 0 )
               {
                  prevWasLimitedProxy = 1;
               }
            }
         }
      }

      free( certDN );
      free( issuerDN );

      if (now < GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0))
      {
         logMsg( 2, "Proxy certificate is not yet valid." );
         foundError |= X509_V_ERR_CERT_NOT_YET_VALID;
      }

      if (now > GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0))
      {
         logMsg( 2, "Proxy certificate expired." );
         foundError |= X509_V_ERR_CERT_HAS_EXPIRED;
      }

      if( foundError ) return foundError;

      prevCert = cert;
   }

   return X509_V_OK;
}

//ADRI: Alternate version for gsi check
unsigned long grid_verifyProxy( STACK_OF(X509) *certstack )
{
   int      i = 0;
   X509    *cert = NULL;
   time_t   now = time((time_t *)NULL);
   size_t   len = 0;             /* Lengths of issuer and cert DN */
   size_t   len2 = 0;            /* Lengths of issuer and cert DN */
   int      prevIsLimited = 0;   /* previous cert was proxy and limited */
   char    *cert_DN = NULL;      /* Pointer to current-certificate-in-certstack's DN */
   char    *issuer_DN = NULL;    /* Pointer to issuer-of-current-cert-in-certstack's DN */
   char    *proxy_part_DN = NULL;
   int      depth = sk_X509_num (certstack);
   int      amount_of_CAs = 0;

   logMsg( 0, "--- Welcome to the grid_verifyProxy function ---");

   // And there was (current) time...
   time(&now);

   // How many CA certs are there in the certstack?
   for(i = 0; i < depth; i++)
   {
      logMsg( 0, "Checking CAness for cert %d", i );
      cert = sk_X509_value(certstack, i);
      cert_DN   = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0);
      if( GRSTx509IsCA( cert ) )
      {
         amount_of_CAs++;

         logMsg( 1, "YES CAness [%s]", cert_DN );
      }
      else
         logMsg( 1, "NO  CAness [%s]", cert_DN );
      free( cert_DN );
   }

   logMsg( 0, "#CA's = %d , depth = %d", amount_of_CAs, depth );

   if ((amount_of_CAs + 2) > depth)
   {
      if ((depth - amount_of_CAs) > 0)
      {
         logMsg( 1, "No proxy certificate in certificate stack to check." );
         return X509_V_OK;
      }
      else
      {
         logMsg( 2, "No personal certificate (neither proxy or user certificate) found in the certficiate stack." );
            return X509_V_ERR_APPLICATION_VERIFICATION;
      }
   }


   /* Changed this value to start checking the proxy and such and
      to skip the CA and the user_cert
   */
   for (i = depth - (amount_of_CAs + 2); i >= 0; i--)
   {
      logMsg( 1, "Checking cert %d", i );
      /* Check for X509 certificate and point to it with 'cert' */
      if ( (cert = sk_X509_value(certstack, i)) != NULL )
      {
         cert_DN   = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0);
         issuer_DN = X509_NAME_oneline( X509_get_issuer_name( cert ),  NULL, 0);
         len       = strlen( cert_DN );
         len2      = strlen( issuer_DN );

         logMsg( 1, "Proxy to verify:" );
         logMsg( 1, "  DN:        %s", cert_DN );
         logMsg( 1, "  Issuer DN: %s", issuer_DN );

         if (now < GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0))
         {
            logMsg( 2, "Proxy certificate is not yet valid." );
            return X509_V_ERR_CERT_NOT_YET_VALID;
         }

         if (now > GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0))
         {
            logMsg( 2, "Proxy certificate expired." );
            return X509_V_ERR_CERT_HAS_EXPIRED;
         }

         /* we reject proxies of limited proxies! */
         if (prevIsLimited)
         {
            logMsg( 2, "Previous proxy was a limited proxy.");
            return X509_V_ERR_INVALID_CA;
         }

         /* User not allowed to sign shortened DN */
         if (len2 > len)
         {
            logMsg( 2, "It is not allowed to sign a shorthened DN.");
            return X509_V_ERR_INVALID_CA;
         }

         /* Proxy subject must begin with issuer. */
         if (strncmp(cert_DN, issuer_DN, len2) != 0)
         {
            logMsg( 2, "Proxy subject must begin with the issuer.");
            return X509_V_ERR_INVALID_CA;
         }

         /* Set pointer to end of base DN in cert_DN */
         proxy_part_DN = &cert_DN[len2];

         /* First attempt at support for Old and New style GSI
            proxies: /CN=anything is ok for now */
         if (strncmp(proxy_part_DN, "/CN=", 4) != 0)
         {
            logMsg( 2, "Could not find a /CN= structure in the DN, thus it is not a proxy.");
            return X509_V_ERR_INVALID_CA;
         }
         else
         {
            logMsg( 1, "Current certificate is a proxy.");
         }


         if ((strncmp(proxy_part_DN, "/CN=limited proxy", 17) == 0) && (i > 0))
         {
            prevIsLimited = 1;
            logMsg( 1, "Found limited proxy.");
         }

         if (cert_DN) free(cert_DN);
         if (issuer_DN) free(issuer_DN);
      }
   }

    return X509_V_OK;
}


/// Check certificate chain for GSI proxy acceptability.
int GRSTx509ChainLoadCheck(GRSTx509Chain **chain,
                           STACK_OF(X509) *certstack, X509 *lastcert,
                           char *capath )
///
/// Returns GRST_RET_OK if valid; OpenSSL X509 errors otherwise.
///
/// The GridSite version handles old and new style Globus proxies, and
/// proxies derived from user certificates issued with "X509v3 Basic
/// Constraints: CA:FALSE" (eg UK e-Science CA)
///
/// TODO: we do not yet check ProxyCertInfo and ProxyCertPolicy extensions
///       (although via GRSTx509KnownCriticalExts() we can accept them.)
{
   X509 *cert;                  /* Points to the current cert in the loop */
   X509 *cacert = NULL;         /* The CA root cert */
   int depth = 0;               /* Depth of cert chain */
   int chain_errors = 0;	/* records previous errors */
   int first_non_ca;		/* number of the EEC issued to user by CA */
   char *ucuserdn = NULL;	/* DN of EEC issued to user by CA */
   size_t len,len2;             /* Lengths of issuer and cert DN */
   int IsCA;                    /* Holds whether cert is allowed to sign */
   int prevIsCA;                /* Holds whether previous cert in chain is
                                   allowed to sign */
   int prevIsLimited;		/* previous cert was proxy and limited */
   int i,ret;                 /* Iteration/temp variables */
   char *proxy_part_DN;         /* Pointer to end part of current-cert-in-chain
                                   maybe eg "/CN=proxy" */
   char *cacertpath;
   unsigned long subjecthash = 0;	/* hash of the name of first cert */
   unsigned long issuerhash = 0;	/* hash of issuer name of first cert */
   FILE *fp;
   time_t now;
   GRSTx509Cert *grst_cert = NULL, *new_grst_cert = NULL;

   time(&now);

   first_non_ca = 0; /* set to something predictable if things fail */

   /* Set necessary preliminary values */
   IsCA          = TRUE;           /* =prevIsCA - start from a CA */
   prevIsLimited = 0;

   /* Get the client cert chain */
   if (certstack != NULL)
     depth = sk_X509_num(certstack); /* How deep is that chain? */

   if ((depth == 0) && (lastcert == NULL))
     {
       *chain = NULL;
       return GRST_RET_FAILED;
     }

   cert = sk_X509_value(certstack, depth - 1);
   subjecthash = X509_NAME_hash(X509_get_subject_name(cert));
   issuerhash = X509_NAME_hash(X509_get_issuer_name(cert));
   asprintf(&cacertpath, "%s/%.8x.0", capath, issuerhash);

   logMsg( 0, "Look for CA root file %s", cacertpath );

   fp = fopen(cacertpath, "r");
   free(cacertpath);

   //Append error if impossible to open CA file
   if (fp == NULL) chain_errors |= GRST_CERT_BAD_CHAIN;
   else
     {
       cacert = PEM_read_X509(fp, NULL, NULL, NULL);
       fclose(fp);
       if (cacert != NULL)
        logMsg( 0, "Loaded CA root cert from file" );
       else
        logMsg( 0 , "Failed to load CA root cert file" );
     }

   *chain = malloc(sizeof(GRSTx509Chain));
   bzero(*chain, sizeof(GRSTx509Chain));

   /* Check the client chain */
   for (i = depth - ((subjecthash == issuerhash) ? 1 : 0);
        i >= ((lastcert == NULL) ? 0 : -1);
        --i)
      /* loop through client-presented chain starting at CA end */
      {
        //GRSTerrorLog(GRST_LOG_DEBUG, "Process cert at depth %d in chain", i);

        prevIsCA=IsCA;

        new_grst_cert = malloc(sizeof(GRSTx509Cert));
        bzero(new_grst_cert, sizeof(GRSTx509Cert));
        new_grst_cert->errors = chain_errors;

        if ((*chain)->firstcert == NULL)
          {
            //GRSTerrorLog(GRST_LOG_DEBUG, "Initialise chain");
            (*chain)->firstcert = new_grst_cert;
          }
        else if(grst_cert) grst_cert->next = new_grst_cert;

        grst_cert = new_grst_cert;

        /* Choose X509 certificate and point to it with 'cert' */
        if (i < 0) cert = lastcert;
        else if (i == depth)
             cert = cacert; /* the self-signed CA from the store*/
        else if ((i == depth - 1) && (subjecthash == issuerhash))
             cert = cacert; /* ie claims to be a copy of a self-signed CA */
        else cert = sk_X509_value(certstack, i);

        if (cert != NULL)
          {
            if ((i == depth - 1) && (subjecthash != issuerhash))
              {
                /* if first cert does not claim to be a self-signed copy
                   of a CA root cert in the store, we check the signature */

                if (cacert == NULL)
                  {
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                    ret = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                  }
                else
                  {
                    ret = X509_check_issued(cacert, cert);

                    logMsg( 0, "Cert sig check %d returns %d", i, ret);

                    if (ret != X509_V_OK)
                             new_grst_cert->errors |= GRST_CERT_BAD_SIG;
                  }
              }
            else if ((i == depth - 2) && (subjecthash == issuerhash))
              {
                /* first cert claimed to be a self-signed copy of a CA root
                cert in the store, we check the signature of the second
                cert, using OUR copy of the CA cert DIRECT from the store */

                if (cacert == NULL)
                  {
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                    ret = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                  }
                else
                  {
                    ret = X509_check_issued(cacert, cert);

                    logMsg( 0, "Cert sig check %d returns %d", i, ret );

                    if (ret != X509_V_OK)
                             new_grst_cert->errors |= GRST_CERT_BAD_SIG;
                  }
              }
            else if (i < depth - 1)
              {
                /* otherwise a normal part of the chain: note that if the
                   first cert claims to be a self-signed copy of a CA root
                   cert in the store, we never use it for sig checking */

                ret = X509_check_issued(sk_X509_value(certstack, i + 1), cert);

                logMsg( 0, "Cert sig check %d returns %d", i, ret );

                if ((ret != X509_V_OK) &&
                    (ret != X509_V_ERR_KEYUSAGE_NO_CERTSIGN))
                          new_grst_cert->errors |= GRST_CERT_BAD_SIG;

                /* NO_CERTSIGN can still be ok due to Proxy Certificates */
              }

            new_grst_cert->serial = (int) ASN1_INTEGER_get(
                               X509_get_serialNumber(cert));
            new_grst_cert->notbefore = GRSTasn1TimeToTimeT(
                               ASN1_STRING_data(X509_get_notBefore(cert)), 0);
            new_grst_cert->notafter  = GRSTasn1TimeToTimeT(
                               ASN1_STRING_data(X509_get_notAfter(cert)), 0);

            /* we check times and record if invalid */

            if (now < new_grst_cert->notbefore)
                 new_grst_cert->errors |= GRST_CERT_BAD_TIME;

            if (now > new_grst_cert->notafter)
                 new_grst_cert->errors |= GRST_CERT_BAD_TIME;

            new_grst_cert->dn = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);
            new_grst_cert->issuer = X509_NAME_oneline(X509_get_issuer_name(cert),NULL,0);
            len       = strlen(new_grst_cert->dn);
            len2      = strlen(new_grst_cert->issuer);

            /* always treat a first cert from the CA files as a
               CA: this is really for lousy CAs that dont create
               proper v3 root certificates */

            if (i == depth) IsCA == TRUE;
            else IsCA = (GRSTx509IsCA(cert) == GRST_RET_OK);

            /* If any forebear certificate is not allowed to sign we must
               assume all decendents are proxies and cannot sign either */
            if (prevIsCA)
              {
                if (IsCA)
                  {
                    new_grst_cert->type = GRST_CERT_TYPE_CA;
                  }
                else
                  {
                    new_grst_cert->type = GRST_CERT_TYPE_EEC;
                    first_non_ca = i;
                    ucuserdn = new_grst_cert->dn;
                    new_grst_cert->delegation
                       = (lastcert == NULL) ? i : i + 1;
                  }
              }
            else
              {
                new_grst_cert->type = GRST_CERT_TYPE_PROXY;

                IsCA = FALSE;
                /* Force proxy check next iteration. Important because I can
                   sign any CA I create! */

                new_grst_cert->delegation = (lastcert == NULL) ? i : i + 1;
              }

            if (!prevIsCA)
              {
                /* issuer didn't have CA status, so this is (at best) a proxy:
                   check for bad proxy extension*/

                if (prevIsLimited) /* we reject proxies of limited proxies! */
                  {
                    new_grst_cert->errors |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }

                /* User not allowed to sign shortened DN */
                if (len2 > len)
                  {
                    new_grst_cert->errors |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }

                /* Proxy subject must begin with issuer. */
                if (strncmp(new_grst_cert->dn, new_grst_cert->issuer, len2) != 0)
                  {
                    new_grst_cert->errors  |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }

                /* Set pointer to end of base DN in cert_DN */
                proxy_part_DN = &(new_grst_cert->dn[len2]);

                /* First attempt at support for Old and New style GSI
                   proxies: /CN=anything is ok for now */
                if (strncmp(proxy_part_DN, "/CN=", 4) != 0)
                  {
                    new_grst_cert->errors  |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }

                if (strncmp(proxy_part_DN, "/CN=limited proxy", 17) == 0)
                        prevIsLimited = 1; /* ready for next cert ... */

                //ADRI: Disable VOMS
                /*
                for (j=0; j < X509_get_ext_count(cert); ++j)
                   {
                     ex = X509_get_ext(cert, j);
                     OBJ_obj2txt(s,sizeof(s),X509_EXTENSION_get_object(ex),1);

                     if (strcmp(s, GRST_VOMS_OID) == 0) // a VOMS extension
                       {
                         GRSTx509ChainVomsAdd(&grst_cert,
                                              new_grst_cert->notbefore,
                                              new_grst_cert->notafter,
                                              ex,
                                              ucuserdn,
                                              vomsdir);
                         grst_cert->delegation = (lastcert == NULL) ? i : i+1;
                       }
                   }
                 */
              }
          }


      } /* end of for loop */

   if (cacert != NULL) X509_free(cacert);

   return GRST_RET_OK;
}

int GRSTx509ChainFree(GRSTx509Chain *chain)
{
   GRSTx509Cert *grst_cert, *next_grst_cert;

   if (chain == NULL) return GRST_RET_OK;

   next_grst_cert = chain->firstcert;

   while (next_grst_cert != NULL)
      {
        grst_cert = next_grst_cert;

        if (grst_cert->issuer != NULL) free(grst_cert->issuer);
        if (grst_cert->dn     != NULL) free(grst_cert->dn);
        if (grst_cert->value  != NULL) free(grst_cert->value);
        if (grst_cert->ocsp   != NULL) free(grst_cert->ocsp);

        next_grst_cert = grst_cert->next;
        free(grst_cert);
      }

   free(chain);

   return GRST_RET_OK;
}

/// Check if certificate can be used as a CA to sign standard X509 certs
int GRSTx509IsCA(X509 *cert)
///
/// Return GRST_RET_OK if true; GRST_RET_FAILED if not.
{
   /* final argument to X509_check_purpose() is whether to check for CAness */

   if (X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 1))
        return GRST_RET_OK;
   else return GRST_RET_FAILED;
}

/*
 Missing funcs:

 mod_ssl
  ssl_callback_SSLVerify()
  ssl_callback_SSLVerify_CRL()

 grid-site
  C GRSTx509KnownCriticalExts()
  C GRSTx509ChainLoadCheck( GRSTx509Chain )
  C GRSTx509ChainFree()
  C GRSTx509IsCA()

  GRST_PROXYCERTINFO_OID
*/

