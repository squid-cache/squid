## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= ext_time_quota_acl
man_MANS= ext_time_quota_acl.8

DEFS += -DDEFAULT_QUOTA_DB=\"$(localstatedir)/ext_time_quota.db\"

ext_time_quota_acl_SOURCES = \
	ext_time_quota_acl.cc

ext_time_quota_acl_LDADD = \
	$(top_builddir)/src/sbuf/libsbuf.la \
	$(top_builddir)/src/debug/libdebug.la \
	$(top_builddir)/src/error/liberror.la \
	$(top_builddir)/src/comm/libminimal.la \
	$(top_builddir)/src/mem/libminimal.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/src/time/libtime.la \
	$(COMPAT_LIB) \
	$(LIBTDB_LIBS)

EXTRA_DIST= ext_time_quota_acl.8 required.m4
