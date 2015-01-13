## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS= ext_wbinfo_group_acl
man_MANS= ext_wbinfo_group_acl.8
EXTRA_DIST= \
	ext_wbinfo_group_acl.8 \
	ext_wbinfo_group_acl.pl.in \
	required.m4

ext_wbinfo_group_acl: ext_wbinfo_group_acl.pl.in
	$(subst_perlshell)

ext_wbinfo_group_acl.8: ext_wbinfo_group_acl
	pod2man ext_wbinfo_group_acl ext_wbinfo_group_acl.8

CLEANFILES += ext_wbinfo_group_acl.8 ext_wbinfo_group_acl
