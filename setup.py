# vim:fileencoding=UTF-8
#
# setup.py
#
# Copyright (C) AB Strakt 2001, All rights reserved
#
# @(#) $Id: setup.py,v 1.3 2008/03/05 23:06:07 rgracian Exp $
#
"""
Installation script for the OpenSSL module
"""
import ez_setup
ez_setup.use_setuptools()
from setuptools import setup, Extension
#from distutils.core import setup, Extension
import os, sys

from version import __version__

openSSLVersion = "0.9.8g"

# A hack to determine if Extension objects support the depends keyword arg.
try:
    init_func = Extension.__init__.func_code
    has_dep = 'depends' in init_func.co_varnames
except:
    has_dep = 0
if not has_dep:
    # If it doesn't, create a local replacement that removes depends
    # from the kwargs before calling the regular constructor.
    _Extension = Extension
    class Extension(_Extension):
        def __init__(self, name, sources, **kwargs):
            if kwargs.has_key('depends'):
                del kwargs['depends']
            apply(_Extension.__init__, (self, name, sources), kwargs)


crypto_src = ['src/crypto/crypto.c', 'src/crypto/x509.c',
              'src/crypto/x509name.c', 'src/crypto/pkey.c',
              'src/crypto/x509store.c', 'src/crypto/x509req.c',
              'src/crypto/x509ext.c', 'src/crypto/pkcs7.c',
              'src/crypto/pkcs12.c', 'src/crypto/netscape_spki.c',
              'src/util.c']
crypto_dep = ['src/crypto/crypto.h', 'src/crypto/x509.h',
              'src/crypto/x509name.h', 'src/crypto/pkey.h',
              'src/crypto/x509store.h', 'src/crypto/x509req.h',
              'src/crypto/x509ext.h', 'src/crypto/pkcs7.h',
              'src/crypto/pkcs12.h', 'src/crypto/netscape_spki.h',
              'src/util.h']
rand_src = ['src/rand/rand.c', 'src/util.c']
rand_dep = ['src/util.h']
ssl_src = ['src/ssl/gsi.c', 'src/ssl/connection.c', 'src/ssl/context.c', 'src/ssl/ssl.c',
           'src/util.c', 'src/ssl/session.c', 'src/ssl/thread_safe.c']
ssl_dep = ['src/ssl/gsi.h', 'src/ssl/connection.h', 'src/ssl/context.h', 'src/ssl/ssl.h',
           'src/util.h', 'src/ssl/session.h', 'src/ssl/thread_safe.h']

IncludeDirs = None
LibraryDirs = None

# Add more platforms here when needed
if os.name == 'nt' or sys.platform == 'win32':
    Libraries = ['libeay32', 'ssleay32', 'Ws2_32']
else:
    Libraries = []
    IncludeDirs = [ '../../external/openssl-%s/openssl-%s/include' % (openSSLVersion, openSSLVersion) ]

#ExtraObjects = [ '/usr/lib/libpthread.a', '/usr/lib/libssl.a','/usr/lib/libcrypto.a' ]
ExtraObjects = [ '../../external/openssl-%s/openssl-%s/libssl.so' % (openSSLVersion, openSSLVersion),
                 '../../external/openssl-%s/openssl-%s/libcrypto.so' % (openSSLVersion, openSSLVersion) ]
                 #, '/usr/lib%s/python%s/config/libpython%s.a' % (sModifier, sys.version[:3], sys.version[:3] ) ]

DefineList = [ ( 'OPENSSL_NO_KRB5', "" ) ]

for confList in ( Libraries, IncludeDirs, ExtraObjects ):
    for index in range( len( confList ) ):
        confList[ index ] = os.path.realpath( confList[ index ] )

def mkExtension(name):
    import string
    modname = 'GSI.%s' % name
    src = globals()['%s_src' % string.lower(name)]
    dep = globals()['%s_dep' % string.lower(name)]
    return Extension(modname, src, libraries=Libraries, depends=dep, include_dirs=IncludeDirs, library_dirs=LibraryDirs, extra_objects=ExtraObjects, define_macros = DefineList)

setup(name='pyGSI', version=__version__,
      package_dir = { 'GSI': '.' },
      ext_modules = [mkExtension('crypto'), mkExtension('rand'), mkExtension('SSL')],
      py_modules  = ['GSI.__init__', 'GSI.tsafe', 'GSI.version'],
      description = 'Python wrapper module around the OpenSSL library (including hack to accept GSI SSL proxies)',
      author = 'Adria Casajus', author_email = 'adria@ecm.ub.es',
      url = 'http://lhcbweb.pic.es',
      license = 'LGPL',
      long_description = """\
High-level wrapper around a subset of the OpenSSL library, includes
 * SSL.Connection objects, wrapping the methods of Python's portable
   sockets
 * Callbacks written in Python
 * Extensive error-handling mechanism, mirroring OpenSSL's error codes
...  and much more ;)"""
     )
