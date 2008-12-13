#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.15 2008/01/08 11:10:48 amosjeffries Exp $
#

AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
CLEANFILES = 

EXTRA_LIBRARIES = libcoss.a libufs.a
noinst_LIBRARIES = @STORE_LIBS@

libcoss_a_SOURCES = \
	coss/store_coss.h \
	coss/store_io_coss.cc \
	coss/store_dir_coss.cc \
	coss/CossSwapDir.h

libufs_a_SOURCES = ufs/store_dir_ufs.cc ufs/store_io_ufs.cc \
	ufs/ufscommon.cci \
	ufs/ufscommon.cc \
	ufs/ufscommon.h 


EXTRA_DIST = \
	coss/coss-notes.txt \
	coss/StoreFScoss.h \
	ufs/StoreFSufs.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src

check_PROGRAMS=testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/fs/ufs/*.h $(top_srcdir)/src/fs/coss/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "ufs" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "coss" || exit 1
## diskd/ has no .h files
## aufs/ has no .h files
## ./ has no .h files

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c

## targets below to emulate distributed makefiles
coss/all: libcoss.a
coss/clean: clean
ufs/all: libufs.a
ufs/clean: clean
