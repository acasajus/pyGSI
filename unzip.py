#!/usr/bin/env python

import zipfile
import os
import sys

if len( sys.argv ) < 2:
 print "Which file to unzip?"
 sys.exit(1)

dest = os.getcwd()
dest = os.path.realpath( dest )
zipName = sys.argv[1]
z = zipfile.ZipFile( zipName, "r" )
for m in z.infolist():
 d = os.path.join( dest, os.path.dirname( m.filename ) )
 try:
  os.makedirs( d )
 except:
  pass
 fd = file( os.path.join( d, os.path.basename( m.filename ) ), "wb" )
 fd.write( z.read( m.filename ) )
 fd.close()
