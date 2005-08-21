#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.13 2005/08/20 21:08:38 serassio Exp $
#

AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

##DIST_SUBDIRS	= coss null ufs

EXTRA_LIBRARIES = libcoss.a libnull.a libufs.a
noinst_LIBRARIES = @STORE_LIBS@

libcoss_a_SOURCES = \
	coss/store_coss.h \
	coss/store_io_coss.cc \
	coss/store_dir_coss.cc \
	coss/CossSwapDir.h

libnull_a_SOURCES = null/store_null.cc null/store_null.h
libufs_a_SOURCES = ufs/store_dir_ufs.cc ufs/store_io_ufs.cc \
	ufs/ufscommon.cci \
	ufs/ufscommon.cc \
	ufs/ufscommon.h 


EXTRA_DIST = \
	coss/coss-notes.txt \
	coss/StoreFScoss.h \
	ufs/StoreFSufs.h \
	null/StoreFSnull.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src

## targets below to emulate distributed makefiles
coss/all: libcoss.a
coss/clean: clean
null/all: libnull.a
null/clean: clean
ufs/all: libufs.a
ufs/clean: clean
