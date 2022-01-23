## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

XPROFSRC= \
	get_tick.h \
	Profiler.cc \
	Profiler.h \
	xprof_type.h

if ENABLE_XPROF_STATS
libprofiler_la_SOURCES = $(XPROFSRC)
noinst_LTLIBRARIES = libprofiler.la
else
EXTRA_DIST = $(XPROFSRC)
endif
