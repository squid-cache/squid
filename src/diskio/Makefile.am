## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

SUBDIRS= $(DISKIO_MODULES)
DIST_SUBDIRS= AIO Blocking DiskDaemon DiskThreads IpcIo Mmapped

noinst_LTLIBRARIES = libdiskio.la

libdiskio_la_SOURCES = \
	DiskFile.h \
	DiskIOModule.cc \
	DiskIOModule.h \
	DiskIOStrategy.h \
	IORequestor.h \
	ReadRequest.cc \
	ReadRequest.h \
	WriteRequest.cc \
	WriteRequest.h

libdiskio_la_LIBADD = $(DISKIO_MODULES_LIBS)
