## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 		= ext_time_quota_acl
man_MANS 			= ext_time_quota_acl.8
EXTRA_DIST			= ext_time_quota_acl.8 required.m4
ext_time_quota_acl_SOURCES	= ext_time_quota_acl.cc

DEFS += -DDEFAULT_QUOTA_DB=\"$(localstatedir)/ext_time_quota.db\" 

LDADD = \
	$(COMPAT_LIB) \
	$(LIB_DB)
