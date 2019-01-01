## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_edirectory_userip_acl

ext_edirectory_userip_acl_SOURCES = \
	ext_edirectory_userip_acl.cc

ext_edirectory_userip_acl_LDADD = \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(XTRA_LIBS)

man_MANS = ext_edirectory_userip_acl.8

EXTRA_DIST = required.m4 ext_edirectory_userip_acl.8
