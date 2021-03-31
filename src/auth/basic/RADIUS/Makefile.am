## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 	= basic_radius_auth
man_MANS 		= basic_radius_auth.8
EXTRA_DIST		= basic_radius_auth.8 required.m4

basic_radius_auth_SOURCES = \
	basic_radius_auth.cc \
	radius-util.cc \
	radius-util.h \
	radius.h

basic_radius_auth_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)
