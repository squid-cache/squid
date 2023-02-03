## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS= ext_kerberos_sid_group_acl
CLEANFILES += ext_kerberos_sid_group_acl
EXTRA_DIST= \
	ext_kerberos_sid_group_acl.pl.in \
	required.m4

ext_kerberos_sid_group_acl: ext_kerberos_sid_group_acl.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = ext_kerberos_sid_group_acl.8
CLEANFILES += ext_kerberos_sid_group_acl.8
EXTRA_DIST += ext_kerberos_sid_group_acl.8

ext_kerberos_sid_group_acl.8: ext_kerberos_sid_group_acl
	pod2man --section=8 ext_kerberos_sid_group_acl ext_kerberos_sid_group_acl.8

endif

