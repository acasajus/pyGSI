#ifndef PyGSI_SSL_THREAD_SAFE_LOCK_H_
#define PyGSI_SSL_THREAD_SAFE_LOCK_H_

#include <Python.h>
#include <unistd.h>
#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>

int initialize_locks( void );
void clean_locks( void );
void locking_thread_callback( int mode, int type, const char *file,
                              int line );

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	unsigned long thread_id( void );
#else
	struct CRYPTO_dynlock_value
	{
		sem_t mutex;
	};

	void update_THREADID( CRYPTO_THREADID* thid );

	struct CRYPTO_dynlock_value *dynlock_create(const char *file, int line);
	void dynlock_lock( int mode, struct CRYPTO_dynlock_value *dLock, const char *file, int line );
	void dynlock_destroy(struct CRYPTO_dynlock_value *dLock, const char *file, int line);

#endif

#endif
