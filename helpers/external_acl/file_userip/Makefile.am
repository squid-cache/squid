## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_file_userip_acl
ext_file_userip_acl_SOURCES = ext_file_userip_acl.cc
man_MANS = ext_file_userip_acl.8

EXTRA_DIST = \
	example.conf \
	example-deny_all_but.conf \
	ext_file_userip_acl.8 \
	required.m4

LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
