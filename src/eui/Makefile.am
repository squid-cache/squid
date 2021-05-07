## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libeui.la

libeui_la_SOURCES = \
	Config.cc \
	Config.h \
	Eui48.cc \
	Eui48.h \
	Eui64.cc \
	Eui64.h

libeui_la_LIBADD = $(EUILIB)
