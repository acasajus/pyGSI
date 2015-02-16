# @(#) $Id$
"""
Installation script for the GSI module
"""
#import ez_setup
#ez_setup.use_setuptools()

from setuptools import setup, Extension
import ConfigParser

import os, sys

here = os.path.realpath( os.path.dirname( __file__ ) )
srcDir = os.path.join( here, "src" )

config = ConfigParser.SafeConfigParser()
config.read( os.path.join( here, "setup.cfg" ) )

def findFiles( baseDir, validFileExts ):
    files = []
    for t in os.walk( baseDir ):
      for fileInDir in t[2]:
        for fext in validFileExts:
          fPos = len( fileInDir ) - len( fext )
          if fileInDir.find( fext, fPos ) == fPos:
            files.append( os.path.join( baseDir, fileInDir ) )
    return files

def createExtension( extName ):
  extDir = os.path.join( srcDir, extName.lower() )
  cFiles = [ os.path.join( srcDir, "util.c" ) ] + findFiles( extDir, ".c" )
  hFiles = [ os.path.join( srcDir, "util.h" ) ] + findFiles( extDir, ".h" )
  extraArgs = {}
  if 'Extensions' in config.sections():
    for k in config.options( 'Extensions' ):
      extraArgs[ k ] = [ v.strip() for v in config.get( 'Extensions', k ).split( " " ) if v.strip() ]
      for i in range( len( extraArgs[k] ) ):
        if os.path.isfile( extraArgs[k][i] ):
          extraArgs[k][i] = os.path.realpath( extraArgs[k][i] )
  return Extension( "GSI.%s" % extName,
                    cFiles,
                    depends = hFiles,
                    libraries = [ 'ssl', 'crypto' ],
                    extra_compile_args = [ "-Wno-deprecated-declarations" ],
                    ** extraArgs
                    )

setup(
  name = "GSI",
  version = "0.6.2",
  author = "Adrian Casajus",
  author_email = "adria@ecm.ub.es",
  description = "Python wrapper module around the OpenSSL library (including hack to accept GSI SSL proxies)",
  license = "GPLv3",
  zip_safe = False,
  #install_requires = [ "distribute>0.6", "pip" ],
  py_modules = ['GSI.__init__', 'GSI.tsafe', 'GSI.version'],
  ext_modules = [ createExtension( extName ) for extName in ( "crypto", "rand", "SSL" ) ]
 )
