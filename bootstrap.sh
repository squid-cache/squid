#! /bin/sh
# Used to setup the configure.in, autoheader and Makefile.in's if configure
# has not been generated. This script is only needed for developers when
# configure has not been run, or if a Makefile.am in a non-configured directory
# has been updated

aclocal \
&& autoheader \
&& automake --foreign --add-missing \
&& autoconf
