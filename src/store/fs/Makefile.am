## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

SUBDIRS= $(STORE_FS_MODULES)
DIST_SUBDIRS= rock ufs

noinst_LTLIBRARIES = libfs.la

libfs_la_SOURCES = \
	Module.cc \
	Module.h

libfs_la_LIBADD = $(STORE_FS_MODULES_LIBS)
