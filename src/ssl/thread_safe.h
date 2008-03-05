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
unsigned long thread_id( void );

#endif
