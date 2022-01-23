## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libecapsquid.la

libecapsquid_la_SOURCES = \
	Config.cc \
	Config.h \
	Host.cc \
	Host.h \
	MessageRep.cc \
	MessageRep.h \
	Registry.h \
	ServiceRep.cc \
	ServiceRep.h \
	XactionRep.cc \
	XactionRep.h

# add libecap using its pkg-config-produced configuration variables
libecapsquid_la_CXXFLAGS = $(EXT_LIBECAP_CFLAGS)
libecapsquid_la_LIBADD = $(EXT_LIBECAP_LIBS)
