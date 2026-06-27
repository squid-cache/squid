## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

noinst_LTLIBRARIES = libbase64.la

libbase64_la_SOURCES = \
	Base64Encoder.cc \
	Base64Encoder.h

libbase64_la_LIBADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LIBNETTLE_LIBS) \
	$(XTRA_LIBS)
