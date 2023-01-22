## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = basic_getpwnam_auth

basic_getpwnam_auth_SOURCES = basic_getpwnam_auth.cc
basic_getpwnam_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(CRYPTLIB)

man_MANS = basic_getpwnam_auth.8

EXTRA_DIST = basic_getpwnam_auth.8 required.m4
