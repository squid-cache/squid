## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= ext_lm_group_acl
man_MANS= ext_lm_group_acl.8

ext_lm_group_acl_SOURCES = ext_lm_group_acl.cc
ext_lm_group_acl_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-lnetapi32 \
	-ladvapi32 \
	-lntdll \
	$(XTRA_LIBS)

EXTRA_DIST= \
	required.m4 \
	ext_lm_group_acl.8
