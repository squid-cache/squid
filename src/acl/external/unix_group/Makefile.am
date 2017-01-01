## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 		= ext_unix_group_acl
man_MANS 			= ext_unix_group_acl.8
EXTRA_DIST			= ext_unix_group_acl.8 required.m4

ext_unix_group_acl_SOURCES= \
	check_group.cc
ext_unix_group_acl_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
