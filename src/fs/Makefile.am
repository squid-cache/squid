#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.10 2003/08/14 23:21:52 robertc Exp $
#

AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

DIST_SUBDIRS	= aufs coss diskd null ufs

EXTRA_LIBRARIES = libaufs.a libcoss.a libdiskd.a libnull.a libufs.a
noinst_LIBRARIES = @STORE_LIBS@

libaufs_a_SOURCES = aufs/aiops.cc aufs/async_io.cc aufs/store_asyncufs.h \
	aufs/store_io_aufs.cc
libcoss_a_SOURCES = coss/store_coss.h   coss/store_io_coss.cc coss/store_dir_coss.cc \
	coss/async_io.cc coss/async_io.h
libdiskd_a_SOURCES = diskd/diskd.cc \
	diskd/store_diskd.h \
	diskd/store_io_diskd.cc

EXTRA_PROGRAMS = diskd/diskd
libexec_PROGRAMS = @STORE_PROGRAMS@
diskd_diskd_SOURCES = diskd/diskd.cc diskd/dio.h
diskd_diskd_LDADD = $(top_builddir)/lib/libmiscutil.a @XTRA_LIBS@

diskd_diskd_INCLUDES = -Idiskd -I$(top_builddir)/include \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/

libnull_a_SOURCES = null/store_null.cc null/store_null.h
libufs_a_SOURCES = ufs/store_dir_ufs.cc ufs/store_io_ufs.cc ufs/store_ufs.h

EXTRA_DIST = \
	coss/coss-notes.txt \
	ufs/IOModule.h \
	coss/StoreFScoss.h \
	ufs/StoreFSufs.h \
	null/StoreFSnull.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src/

## targets below to emulate distributed makefiles
aufs/all: libaufs.a
aufs/clean: clean
coss/all: libcoss.a
coss/clean: clean
diskd/all: libdiskd.a
diskd/clean: clean
null/all: libnull.a
null/clean: clean
ufs/all: libufs.a
ufs/clean: clean
