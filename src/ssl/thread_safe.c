
#include <Python.h>
#include <pythread.h>
#define SSL_MODULE
#include "ssl.h"
#include "thread_safe.h"
#include <openssl/opensslv.h>

static sem_t *lock_cs = NULL;
static long *lock_count = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	unsigned long
	thread_id( void )
	{
		unsigned long thId = 0;

		thId = PyThread_get_thread_ident(  );
		return thId;
	}
#else
	void
	update_THREADID( CRYPTO_THREADID* thid )
	{
		CRYPTO_THREADID_set_numeric( thid, PyThread_get_thread_ident() );
	}

	struct CRYPTO_dynlock_value *
	dynlock_create(const char *file, int line)
	{
		struct CRYPTO_dynlock_value *dLock = OPENSSL_malloc( sizeof( struct CRYPTO_dynlock_value ) );
		if ( ! sem_init( &( dLock->mutex ), 0, 1 ) )
		{
				return NULL;
		}
		return dLock;
	}

	void
	dynlock_lock( int mode, struct CRYPTO_dynlock_value *dLock, const char *file, int line )
	{
		if( mode && dLock )
			sem_wait( &( dLock->mutex ) );
		else
			sem_post( &( dLock->mutex ) );
	}

	void
	dynlock_destroy(struct CRYPTO_dynlock_value *dLock, const char *file, int line)
	{
		sem_destroy( &( dLock->mutex ) );
		OPENSSL_free( dLock );
	}

#endif


int
initialize_locks(  )
{
    int i;
    int ok = 1;

    lock_cs = OPENSSL_malloc( CRYPTO_num_locks(  ) * sizeof( sem_t ) );
    lock_count = OPENSSL_malloc( CRYPTO_num_locks(  ) * sizeof( long ) );
    for ( i = 0; i < CRYPTO_num_locks(  ); i++ )
    {
        lock_count[i] = 0;
        if ( sem_init( &( lock_cs[i] ), 0, 1 ) == -1 )
            ok = 0;
    }

    CRYPTO_set_locking_callback( ( void ( * )
                                   ( int, int, const char *,
                                     int ) ) locking_thread_callback );
#if OPENSSL_VERSION_NUMBER < 0x10000000L
    CRYPTO_set_id_callback( thread_id );
#else
   	CRYPTO_THREADID_set_callback( update_THREADID );
   	CRYPTO_set_dynlock_create_callback( dynlock_create );
   	CRYPTO_set_dynlock_lock_callback( dynlock_lock );
   	CRYPTO_set_dynlock_destroy_callback( dynlock_destroy );
#endif

    return ok;
}

void
clean_locks( void )
{
    int i;

    CRYPTO_set_locking_callback( NULL );

    for ( i = 0; i < CRYPTO_num_locks(  ) && lock_cs != NULL; i++ )
    {
        sem_destroy( &( lock_cs[i] ) );
    }
    OPENSSL_free( lock_cs );
    OPENSSL_free( lock_count );
    lock_cs = NULL;
    lock_count = NULL;
}

void
locking_thread_callback( int mode, int type, const char *file, int line )
{
#ifdef GSI_LOCK_DEBUG
    fprintf( stderr, "thread=%4ul mode=%s lock=%s %s:%d\n",
             CRYPTO_thread_id(  ),
             ( mode & CRYPTO_LOCK ) ? "l" : "u",
             ( type & CRYPTO_READ ) ? "r" : "w", file, line );
#endif

    if ( mode & CRYPTO_LOCK )
    {
        sem_wait( &( lock_cs[type] ) );
        lock_count[type]++;
    }
    else
    {
        sem_post( &( lock_cs[type] ) );
    }
}



