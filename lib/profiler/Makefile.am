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
