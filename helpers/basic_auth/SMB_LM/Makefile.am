## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = basic_smb_lm_auth

basic_smb_lm_auth_SOURCES = \
	msntauth.cc \
	msntauth.h \
	valid.cc \
	valid.h

EXTRA_DIST = \
	msntauth-v2.0.lsm \
	README.html \
	required.m4

LDADD = \
	$(top_builddir)/lib/smblib/libsmblib.la \
	$(top_builddir)/lib/rfcnb/librfcnb.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/lib
