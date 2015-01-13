## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

man_MANS = digest_file_auth.8
libexec_PROGRAMS = digest_file_auth
digest_file_auth_SOURCES = digest_file_auth.cc \
	digest_common.h \
	text_backend.cc \
	text_backend.h

LDADD = \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = digest_file_auth.8 required.m4
