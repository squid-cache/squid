## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

DIST_SUBDIRS= fs id_rewriters
SUBDIRS= id_rewriters

noinst_LTLIBRARIES = libstore.la

libstore_la_SOURCES = \
	Controlled.h \
	Controller.cc \
	Controller.h \
	Disk.cc \
	Disk.h \
	Disks.cc \
	Disks.h \
	LocalSearch.cc \
	LocalSearch.h \
	ParsingBuffer.cc \
	ParsingBuffer.h \
	Storage.h \
	SwapMeta.cc \
	SwapMeta.h \
	SwapMetaIn.cc \
	SwapMetaIn.h \
	SwapMetaOut.cc \
	SwapMetaOut.h \
	SwapMetaView.cc \
	SwapMetaView.h \
	forward.h

if ENABLE_STORE_FS
SUBDIRS += fs
libstore_la_LIBADD = fs/libfs.la
endif
