## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

EXTRA_DIST= required.m4

libexec_PROGRAMS= negotiate_wrapper_auth

negotiate_wrapper_auth_SOURCES= \
	negotiate_wrapper.cc
negotiate_wrapper_auth_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(XTRA_LIBS)
