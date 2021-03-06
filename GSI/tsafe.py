from GSI import SSL
_ssl = SSL
del SSL

import threading
_RLock = threading.RLock
del threading

class Connection:
    def __init__(self, *args):
        self._ssl_conn = apply(_ssl.Connection, args)
        self._lock = _RLock()

    for f in ('get_context', 'pending', 'send', 'write', 'recv', 'read',
              'renegotiate', 'bind', 'listen', 'connect', 'accept',
              'setblocking', 'fileno', 'shutdown', 'close', 'get_cipher_list',
              'getpeername', 'getsockname', 'getsockopt', 'setsockopt',
              'makefile', 'get_app_data', 'set_app_data', 'state_string',
              'sock_shutdown', 'get_peer_certificate', 'want_read',
              'want_write', 'set_connect_state', 'set_accept_state',
              'connect_ex', 'sendall'):
        exec """def %s(self, *args):
            self._lock.acquire()
            try:
                return apply(self._ssl_conn.%s, args)
            finally:
                self._lock.release()\n""" % (f, f)

