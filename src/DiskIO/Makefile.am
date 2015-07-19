## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

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

EXTRA_DIST = modules.sh

