## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libAIO.la

libAIO_la_SOURCES = \
	AIODiskFile.cc \
	AIODiskFile.h \
	AIODiskIOModule.cc \
	AIODiskIOModule.h \
	AIODiskIOStrategy.cc \
	AIODiskIOStrategy.h \
	async_io.h

if ENABLE_WIN32_AIO
libAIO_la_SOURCES += \
	aio_win32.cc \
	aio_win32.h
else
EXTRA_DIST = \
	aio_win32.cc \
	aio_win32.h
endif

