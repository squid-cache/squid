#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2002/05/20 02:03:58 hno Exp $
#

AUTOMAKE_OPTIONS = subdir-objects

DIST_SUBDIRS	= aufs coss diskd null ufs
SUBDIRS		= @STORE_MODULE_SUBDIRS@

EXTRA_LIBRARIES = libaufs.a libcoss.a libdiskd.a libnull.a libufs.a
noinst_LIBRARIES = @STORE_LIBS@

libaufs_a_SOURCES = aufs/aiops.c aufs/async_io.c aufs/store_asyncufs.h \
	aufs/store_dir_aufs.c aufs/store_io_aufs.c
libcoss_a_SOURCES = coss/store_coss.h   coss/store_io_coss.c coss/store_dir_coss.c \
	coss/async_io.c coss/async_io.h
libdiskd_a_SOURCES = diskd/diskd.c diskd/store_dir_diskd.c diskd/store_diskd.h \
	diskd/store_io_diskd.c
libnull_a_SOURCES = null/store_null.c
libufs_a_SOURCES = ufs/store_dir_ufs.c ufs/store_io_ufs.c ufs/store_ufs.h

EXTRA_DIST = \
	coss/coss-notes.txt

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src/

## targets below to emulate distributed makefiles
aufs/all: libaufs.a
aufs/clean: clean
coss/all: libcoss.a
coss/clean: clean
null/all: libnull.a
null/clean: clean
ufs/all: libufs.a
ufs/clean: clean
