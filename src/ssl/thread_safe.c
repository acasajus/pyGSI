
#include <Python.h>
#include <pythread.h>
#define SSL_MODULE
#include "ssl.h"

static sem_t *lock_cs = NULL;
static long *lock_count = NULL;

int initialize_locks(  )
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
	CRYPTO_set_id_callback( thread_id );

	return ok;
}

void clean_locks( void )
{
	int i;

	CRYPTO_set_locking_callback( NULL );
//  fprintf(stderr,"cleanup\n");
	for ( i = 0; i < CRYPTO_num_locks(  ) && lock_cs != NULL; i++ )
	{
		sem_destroy( &( lock_cs[i] ) );
//      fprintf(stderr,"%8ld:%s\n",lock_count[i], CRYPTO_get_lock_name(i));
	}
	OPENSSL_free( lock_cs );
	OPENSSL_free( lock_count );
	lock_cs = NULL;
	lock_count = NULL;

//  fprintf(stderr,"done cleanup\n");
}

void locking_thread_callback( int mode, int type, const char *file,
							  int line )
{
#ifdef DEBUG
	fprintf( stderr, "thread=%4ul mode=%s lock=%s %s:%d\n",
			 CRYPTO_thread_id(  ),
			 ( mode & CRYPTO_LOCK ) ? "l" : "u",
			 ( type & CRYPTO_READ ) ? "r" : "w", file, line );
#endif
/*
	if (CRYPTO_LOCK_SSL_CERT == type)
		fprintf(stderr,"(t,m,f,l) %ld %d %s %d\n",
		CRYPTO_thread_id(),
		mode,file,line);
*/
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

unsigned long thread_id( void )
{
	unsigned long thId = 0;

//  Py_BEGIN_ALLOW_THREADS
	thId = PyThread_get_thread_ident(  );
   //thId = (unsigned long) pthread_self(void);
//  Py_END_ALLOW_THREADS
//  printf("ThId %d\n",thId);
	return thId;
}
