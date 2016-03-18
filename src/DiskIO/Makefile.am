## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

SUBDIRS=
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

# Custom DiskIO modules (if any):
libdiskio_la_LIBADD = $(DISK_LIBS)

# Optional DiskIO modules:

if ENABLE_DISKIO_AIO
SUBDIRS += AIO
libdiskio_la_LIBADD += AIO/libAIO.la $(AIOLIB)
endif

if ENABLE_DISKIO_BLOCKING
SUBDIRS += Blocking
libdiskio_la_LIBADD += Blocking/libBlocking.la
endif

if ENABLE_DISKIO_DISKDAEMON
SUBDIRS += DiskDaemon
libdiskio_la_LIBADD += DiskDaemon/libDiskDaemon.la
endif

if ENABLE_DISKIO_DISKTHREADS
SUBDIRS += DiskThreads
libdiskio_la_LIBADD += DiskThreads/libDiskThreads.la $(LIBPTHREADS)
endif

if ENABLE_DISKIO_IPCIO
SUBDIRS += IpcIo
libdiskio_la_LIBADD += IpcIo/libIpcIo.la
endif

if ENABLE_DISKIO_MMAPPED
SUBDIRS += Mmapped
libdiskio_la_LIBADD += Mmapped/libMmapped.la
endif

