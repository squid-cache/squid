## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libDiskDaemon.la
libexec_PROGRAMS = diskd

libDiskDaemon_la_SOURCES = \
	DiskDaemonDiskIOModule.cc \
	DiskDaemonDiskIOModule.h \
	DiskdAction.cc \
	DiskdAction.h \
	DiskdFile.cc \
	DiskdFile.h \
	DiskdIOStrategy.cc \
	DiskdIOStrategy.h \
	diomsg.h

diskd_SOURCES = diskd.cc
nodist_diskd_SOURCES = time.cc
diskd_LDADD = \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

time.cc: $(top_srcdir)/src/time.cc
	cp $(top_srcdir)/src/time.cc time.cc

CLEANFILES += time.cc
