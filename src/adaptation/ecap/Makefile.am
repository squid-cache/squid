## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsquid-ecap.la

libsquid_ecap_la_SOURCES = \
	Config.h \
	Config.cc \
	Host.h \
	Host.cc \
	MessageRep.h \
	MessageRep.cc \
	ServiceRep.h \
	ServiceRep.cc \
	XactionRep.h \
	XactionRep.cc \
	\
	Registry.h

# add libecap using its pkg-config-produced configuration variables
libsquid_ecap_la_CXXFLAGS = $(EXT_LIBECAP_CFLAGS)
libsquid_ecap_la_LIBADD = $(EXT_LIBECAP_LIBS) 
