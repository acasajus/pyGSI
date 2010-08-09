#!/usr/bin/env python

import imp, os, sys, platform

here = os.path.dirname( os.path.abspath( __file__ ) )
chFilePath = os.path.join( os.path.dirname( here ) , "common", "CompileHelper.py" )
try:
  fd = open( chFilePath )
except Exception, e:
  print "Cannot open %s: %s" % ( chFilePath, e )
  sys.exit( 1 )

chModule = imp.load_module( "CompileHelper", fd, chFilePath, ( ".py", "r", imp.PY_SOURCE ) )
fd.close()
chClass = getattr( chModule, "CompileHelper" )

compileOpenSSL = False

if compileOpenSSL:
  osslch = chClass( os.path.join( here, "openssl" ) )

  versions = { 'openssl' : "0.9.8m" }
  osslch.setPackageVersions( versions )

  osslch.unTarPackage( "openssl" )
  ret = osslch.execRawAndGetOutput( "gcc -dumpversion" )

  if not osslch.doConfigure( "openssl", extraArgs = "shared threads", configureExecutable = "config" ):
    osslch.ERROR( "Could not deploy openssl package" )
    sys.exit( 1 )

  if ret:
    if ret[0].strip() >= "4.3.0":
      makefilePath = os.path.join( osslch.getPackageDir( 'openssl' ), 'Makefile' )
      osslch.INFO( "Patching %s" % makefilePath )
      osslch.replaceInFile( makefilePath, "-m486", "-mtune=i486" )

  if not osslch.doMake( "openssl", makeJobs = 1 ):
    osslch.ERROR( "Could not deploy openssl package" )
    sys.exit( 1 )

ch = chClass( here )

prefix = ch.getPrefix()

libPaths = []
for lp in ( "lib", "lib64" ):
  lp = os.path.join( prefix, lp )
  if os.path.isdir( lp ):
    libPaths.append( lp )

fd = open( os.path.join( here, "setup.cfg" ), "w" )
fd.write( 
""" 
[build_ext]
include_dirs = %s
library_dirs = %s
define = OPENSSL_NO_KRB5
verbose = 1         
""" % ( os.path.join( prefix, "include" ), ":".join( libPaths ) )
 )
fd.close()


#for step in ( "build", "bdist_egg" ):
#  if not ch.pythonExec( "setup.py", extraArgs = step ):
#    ch.ERROR( "Could not deploy GSI" )
#    sys.exit( 1 )


if not ch.easyInstall( here ):
  ch.ERROR( "Could not deploy GSI" )
  sys.exit( 1 )
