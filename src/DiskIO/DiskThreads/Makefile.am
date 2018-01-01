## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libDiskThreads.la

libDiskThreads_la_SOURCES = \
	async_io.cc \
	CommIO.cc \
	CommIO.h \
	DiskThreads.h \
	DiskThreadsDiskFile.cc \
	DiskThreadsDiskFile.h \
	DiskThreadsDiskIOModule.cc \
	DiskThreadsDiskIOModule.h \
	DiskThreadsIOStrategy.cc \
	DiskThreadsIOStrategy.h

if ENABLE_WIN32_AIOPS
libDiskThreads_la_SOURCES += aiops_win32.cc
EXTRA_DIST = aiops.cc
else
libDiskThreads_la_SOURCES += aiops.cc
EXTRA_DIST = aiops_win32.cc
endif

