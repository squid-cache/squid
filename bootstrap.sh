#!/bin/sh
# Used to setup the configure.in, autoheader and Makefile.in's if configure
# has not been generated. This script is only needed for developers when
# configure has not been run, or if a Makefile.am in a non-configured directory
# has been updated

# Autotool versions required
acver="2.13"
amver="1.5"

bootstrap() {
  if "$@"; then
    true # Everything OK
  else
    echo "$1 failed"
    echo "Autotool bootstrapping failed. You will need to investigate and correct" ;
    echo "before you can develop on this source tree" 
    exit 1
  fi
}

# Make sure cfgaux exists
mkdir -p cfgaux

# Adjust paths of required autool packages
if autoconf --version | grep -q $acver; then
  acver=""
fi
if automake --version | grep -q $amver; then
  amver=""
fi
acver=`echo $acver | sed -e 's/\.//'`
amver=`echo $amver | sed -e 's/\.//'`

# Bootstrap the autotool subsystems
bootstrap aclocal$amver
bootstrap autoheader$acver
bootstrap automake$amver --foreign --add-missing
bootstrap autoconf$acver

echo "Autotool bootstrapping complete."
