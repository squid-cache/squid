#! /bin/sh
# Used to setup the configure.in, autoheader and Makefile.in's if configure
# has not been generated. This script is only needed for developers when
# configure has not been run, or if a Makefile.am in a non-configured directory
# has been updated

if ! ( aclocal ) ; then
  echo "aclocal failed" 
else
  if ! ( autoheader ) ; then
    echo "autoheader failed"
  else
    if ! ( automake --foreign --add-missing ) ; then
      echo "automake failed"
    else
      if ! ( autoconf ) ; then
	echo "autoconf failed"
      else
	echo "Autotool bootstrapping complete."
	exit 0
      fi
    fi
  fi
fi

echo "Autotool bootstrapping failed. You will need to investigate and correct" ;
echo "before you can develop on this source tree" 
