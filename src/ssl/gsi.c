#include "ssl.h"

/* Later OpenSSL versions add a second pointer ... */
int
gsiVerifyCertWrapper( X509_STORE_CTX * ctx, void *p )

/* Earlier ones have a single argument ... */
// int GRST_verify_cert_wrapper(X509_STORE_CTX *ctx)

/* Before 0.9.7 we cannot change the check_issued callback directly in
   the X509_STORE, so we must insert it in another callback that gets
   called early enough */
{
    ctx->check_issued = gsiCheckIssuedWrapper;

    /*Allow proxies*/
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
    return X509_verify_cert( ctx );
}

int
gsiCheckIssuedWrapper( X509_STORE_CTX * ctx, X509 * x, X509 * issuer )

/* We change the default callback to use our wrapper and discard errors
   due to GSI proxy chains (ie where users certs act as CAs) */
{
    int ret;
    char *dummy;

    logMsg( 1, "Wrapper called" );
    dummy = X509_NAME_oneline( X509_get_subject_name( x ), NULL, 0 );
    logMsg( 0, " Subject [%s]", dummy );
    if ( dummy )
        OPENSSL_free( dummy );
    dummy = X509_NAME_oneline( X509_get_issuer_name( issuer ), NULL, 0 );
    logMsg( 0, " Issuer [%s]", dummy );
    if ( dummy )
        OPENSSL_free( dummy );



    ret = X509_check_issued( issuer, x );
    if ( ret == X509_V_OK )
        return 1;

    /* Non self-signed certs without signing are ok if they passed
       the other checks inside X509_check_issued. Is this enough? */
    if ( ( ret == X509_V_ERR_KEYUSAGE_NO_CERTSIGN ) &&
         ( X509_NAME_cmp( X509_get_subject_name( issuer ),
                          X509_get_subject_name( x ) ) != 0 ) )
        return 1;

    /* If we haven't asked for issuer errors don't set ctx */
#if OPENSSL_VERSION_NUMBER < 0x00908000
    if ( !( ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK ) )
        return 0;
#else
    if ( !( ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK ) )
        return 0;
#endif

    ctx->error = ret;
    ctx->current_cert = x;
    ctx->current_issuer = issuer;
    return ctx->verify_cb( 0, ctx );
}

int
gsiVerifyCallback( int ok, X509_STORE_CTX * ctx )
{

    int errnum = X509_STORE_CTX_get_error( ctx );
    int errdepth = X509_STORE_CTX_get_error_depth( ctx );
    int rawOK = ok;             //Is openssl telling us the cert is ok?
    SSL *ssl = ( SSL * ) X509_STORE_CTX_get_app_data( ctx );    //SSL connection
    ssl_ConnectionObj *conn = ( ssl_ConnectionObj * ) SSL_get_app_data( ssl );  //Python connection

    STACK_OF( X509 ) * certstack;
    X509 *cert;

#ifdef GSI_HANDSHAKE_DEBUG
    char *dummy;
    logMsg( 0, "GSI HANDSHAKE" );
#endif

    cert = X509_STORE_CTX_get_current_cert( ctx );

#ifdef GSI_HANDSHAKE_DEBUG
    logMsg( 0, "===============" );
    dummy = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0 );
    logMsg( 0, "Subject [%s]", dummy );
    if ( dummy )
        OPENSSL_free( dummy );
    dummy = X509_NAME_oneline( X509_get_issuer_name( cert ), NULL, 0 );
    logMsg( 0, "Issuer [%s]", dummy );
    if ( dummy )
        OPENSSL_free( dummy );
#endif
    //context = SSL_get_SSL_CTX(cert);

    /*
     * GSI Proxy user-cert-as-CA handling:
     * we skip Invalid CA errors at this stage, since we will check this
     * again at errdepth=0 for the full chain using GRSTx509ChainLoadCheck
     */
    logMsg( 0, "errnum %d INV_CA %d", errnum, X509_V_ERR_INVALID_CA );
    logMsg( 0, "errnum %d INVALID_PURPOSE %d", errnum,
            X509_V_ERR_INVALID_PURPOSE );
    if ( errnum == X509_V_ERR_INVALID_CA
         || errnum == X509_V_ERR_INVALID_PURPOSE )
    {
        if ( gsiCheckIsCA( cert ) )
        {
            ok = TRUE;
            errnum = X509_V_OK;
            X509_STORE_CTX_set_error( ctx, errnum );
        }
    }

    /*
     * New style GSI Proxy handling, with critical ProxyCertInfo
     * extension: we use gsiCheckKnownCriticalExt() to check this
     */
    logMsg( 0, "errnum %d UNH_CRITICAL_EXT %d", errnum,
            X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION );
    if ( errnum == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION )
    {
        if ( gsiCheckKnownCriticalExt
             ( X509_STORE_CTX_get_current_cert( ctx ) ) == GSI_RET_OK )
        {
            logMsg( 0,
                    "gsiCheckKnownCriticalExt() accepts previously:  Unhandled Critical Extension (GSI Proxy?)" );

            ok = TRUE;
            errnum = X509_V_OK;
            X509_STORE_CTX_set_error( ctx, errnum );
        }
    }


    //ADRI:mod_ssl callback?
    //returned_ok = ssl_callback_SSLVerify(ok, ctx);
    /* in case ssl_callback_SSLVerify changed it */
    //errnum = X509_STORE_CTX_get_error(ctx);


    logMsg( 0, "OK %d Errdepth %d errnum %d == %d ", ok, errdepth, errnum,
            X509_V_OK );
    logMsg( 0, " errnum %d -> %s", errnum,
            X509_verify_cert_error_string( errnum ) );

    if ( errdepth == 0 && rawOK )
        /*
         * We've now got the last certificate - the identity being used for
         * this connection. At this point we check the whole chain for valid
         * CAs or, failing that, GSI-proxy validity using GRSTx509CheckChain.
         */
    {
        logMsg( 0, "Checking x509 chain" );
        certstack = ( STACK_OF( X509 ) * ) X509_STORE_CTX_get_chain( ctx );

        //errnum = GRSTx509ChainLoadCheck(&grst_chain, certstack, NULL,
        //                            "/home/adria/Devel/DIRAC3/etc/grid-security/certificates/" );
        //GRSTx509ChainFree(grst_chain);

        //errnum = grid_verifyProxy( certstack );
        errnum = gsiVerifyProxyChain( certstack );
        X509_STORE_CTX_set_error( ctx, errnum );

        if ( errnum != X509_V_OK )
        {
            logMsg( 0,
                    "Invalid certificate chain reported by gsiVerifyProxyChain()" );
            ok = FALSE;
        }
        else
        {
            logMsg( 0,
                    "Valid certificate chain reported by gsiVerifyProxyChain()" );
            conn->remoteCertVerified = 1;
        }

    }

    logMsg( 0, "Final OK: %d X509Error: %d (%s)", ok, errnum, X509_verify_cert_error_string( errnum ) );

    if ( !ok )
        conn->handshakeErrorId = errnum;

    return ok;
}

/// Check critical extensions
int
gsiCheckKnownCriticalExt( X509 * cert )
///
/// Returning GSI_RET_OK if all of extensions are known to us or
/// OpenSSL; GRST_REF_FAILED otherwise.
///
/// This function relies on functionality (X509_supported_extension)
/// introduced in 0.9.7.
{
    int i;
    char s[80];
    X509_EXTENSION *ex;

    for ( i = 0; i < X509_get_ext_count( cert ); ++i )
    {
        ex = X509_get_ext( cert, i );

        if ( X509_EXTENSION_get_critical( ex ) &&
             !X509_supported_extension( ex ) )
        {
            OBJ_obj2txt( s, sizeof( s ), X509_EXTENSION_get_object( ex ), 1 );

            if ( strcmp( s, GSI_PROXYCERTINFO_OID ) != 0 )
                return GSI_RET_FAILED;
        }
    }

    return GSI_RET_OK;
}

//ADRI:Rocking version of the verification
unsigned long
gsiVerifyProxyChain( STACK_OF( X509 ) * certstack )
{
    int depth = sk_X509_num( certstack );       //Number of certs in stack
    int prevWasCA = 1;          //Initial cert is a CA
    int prevWasLimitedProxy = 0;        //Initial cert is not a limited proxy
    int isLimited;
    int i;
    int claimsCABehaviour;
    int lenSubject, lenIssuer;
    int foundError = 0;
    char *certDN;
    char *issuerDN;
    char *proxyDNchunk;
    X509 *prevCert, *cert;
    time_t now;

    //Set current time
    time( &now );

    //Get top level CA cert in stack
    prevCert = sk_X509_value( certstack, depth - 1 );

    for ( i = depth - 2; i >= 0; i-- )
    {
        logMsg( 1, "---" );
        cert = sk_X509_value( certstack, i );

        certDN = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0 );
        issuerDN = X509_NAME_oneline( X509_get_issuer_name( cert ), NULL, 0 );
        lenSubject = strlen( certDN );
        lenIssuer = strlen( issuerDN );

        logMsg( 1, "Checking subject [%s]", certDN );
        logMsg( 1, "Checking issuer  [%s]", issuerDN );

        //Checking the issuer has already been done by openSSL and the main wrapper

        claimsCABehaviour = gsiCheckIsCA( cert );

        //Is a normal CA cert
        if ( !claimsCABehaviour )
        {
        	logMsg( 1, " Claims CA behaviour" );
            //If previous wasn't a CA then error!
            if ( !prevWasCA )
            {
            	logMsg( 1, " ERR: Prev wasn't CA" );
                foundError |= X509_V_ERR_APPLICATION_VERIFICATION;
            }
            //Seems ok
            prevWasCA = 1;
        }
        //Can be either a user cert or a proxy
        else
        {
        	logMsg( 1, " No CA Behaviour" );
            //Has to be a user cert issued by a real CA
            if ( prevWasCA )
            {
            	logMsg( 1, " Prev was CA" );
                prevWasCA = 0;
            }
            //Proxy!!!
            else
            {
                /* User not allowed to sign shortened DN */
                if ( lenIssuer > lenSubject )
                {
                    logMsg( 2, " ERR: It is not allowed to sign a shorthened DN." );
                    foundError |= X509_V_ERR_INVALID_CA;
                }
                /* Proxy subject must begin with issuer. */
                else if ( strncmp( certDN, issuerDN, lenIssuer ) != 0 )
                {
                    logMsg( 2, " ERR:Proxy subject must begin with the issuer." );
                    foundError |= X509_V_ERR_INVALID_CA;
                }
                else
                {
                    /* Set pointer to end of base DN in cert_DN */
                    proxyDNchunk = &certDN[lenIssuer];

                    /* First attempt at support for Old and New style GSI
                       proxies: /CN=anything is ok for now */
                    if ( strncmp( proxyDNchunk, "/CN=", 4 ) != 0 )
                    {
                        logMsg( 2,
                                "Could not find a /CN= structure in the DN, thus it is not a proxy." );
                        foundError |= X509_V_ERR_INVALID_CA;
                    }
                    //We don't accept proxies of limited ones
                    if ( prevWasLimitedProxy && strncmp( proxyDNchunk, "/CN=proxy", 9 ) ==
                                             0 )
                                        {
                    	logMsg( 2, " ERR: Prev was limited" );
                        foundError |= X509_V_ERR_APPLICATION_VERIFICATION;
                    }
                    //If it's limited
                    isLimited = strncmp( proxyDNchunk, "/CN=limited proxy", 17 ) == 0;
                    if( prevWasLimitedProxy && ! isLimited )
                    {
                    	logMsg( 2, "ERR: Prev was limited and this step is not (%s)", proxyDNchunk );
                    	foundError |= X509_V_ERR_APPLICATION_VERIFICATION;
                    }
                    if ( isLimited )
                    	prevWasLimitedProxy = 1;
                }
            }
        }

        free( certDN );
        free( issuerDN );

        if ( now <
             gsiAsn1TimeToTimeT( ASN1_STRING_data
                                 ( X509_get_notBefore( cert ) ), 0 ) )
        {
            logMsg( 2, "Proxy certificate is not yet valid." );
            foundError |= X509_V_ERR_CERT_NOT_YET_VALID;
        }

        if ( now >
             gsiAsn1TimeToTimeT( ASN1_STRING_data
                                 ( X509_get_notAfter( cert ) ), 0 ) )
        {
            logMsg( 2, "Proxy certificate expired." );
            foundError |= X509_V_ERR_CERT_HAS_EXPIRED;
        }

        if ( foundError )
            return foundError;

        prevCert = cert;
    }

    return X509_V_OK;
}

/// Check if certificate can be used as a CA to sign standard X509 certs
int
gsiCheckIsCA( X509 * cert )
///
/// Return GSI_RET_OK if true; GSI_RET_FAILED if not.
{
    /* final argument to X509_check_purpose() is whether to check for CAness */

    if ( X509_check_purpose( cert, X509_PURPOSE_SSL_CLIENT, 1 ) )
        return GSI_RET_OK;
    else
        return GSI_RET_FAILED;
}

/// ASN1 time string (in a char *) to time_t

/**
 *  (Use ASN1_STRING_data() to convert ASN1_GENERALIZEDTIME to char * if
 *   necessary)
 */

time_t
gsiAsn1TimeToTimeT( unsigned char *asn1time, size_t len )
{
    char zone;
    struct tm time_tm;

    if ( len == 0 )
        len = strlen( ( char * ) asn1time );

    if ( ( len != 13 ) && ( len != 15 ) )
        return 0;               /* dont understand */

    if ( ( len == 13 ) &&
         ( ( sscanf( ( char * ) asn1time, "%02d%02d%02d%02d%02d%02d%c",
                     &( time_tm.tm_year ),
                     &( time_tm.tm_mon ),
                     &( time_tm.tm_mday ),
                     &( time_tm.tm_hour ),
                     &( time_tm.tm_min ),
                     &( time_tm.tm_sec ),
                     &zone ) != 7 ) || ( zone != 'Z' ) ) )
        return 0;               /* dont understand */

    if ( ( len == 15 ) &&
         ( ( sscanf( ( char * ) asn1time, "20%02d%02d%02d%02d%02d%02d%c",
                     &( time_tm.tm_year ),
                     &( time_tm.tm_mon ),
                     &( time_tm.tm_mday ),
                     &( time_tm.tm_hour ),
                     &( time_tm.tm_min ),
                     &( time_tm.tm_sec ),
                     &zone ) != 7 ) || ( zone != 'Z' ) ) )
        return 0;               /* dont understand */

    /* time format fixups */

    if ( time_tm.tm_year < 90 )
        time_tm.tm_year += 100;
    --( time_tm.tm_mon );

    return timegm( &time_tm );
}
