include $(top_srcdir)/src/Common.am

libexec_SCRIPTS = ext_wbinfo_group_acl
EXTRA_DIST	= ext_wbinfo_group_acl.pl.in required.m4

ext_wbinfo_group_acl: ext_wbinfo_group_acl.pl.in
	$(subst_perlshell)

EXTRA_DIST += ext_wbinfo_group_acl.8
man_MANS = ext_wbinfo_group_acl.8

ext_wbinfo_group_acl.8: ext_wbinfo_group_acl.pl.in
	pod2man $(srcdir)/ext_wbinfo_group_acl.pl.in ext_wbinfo_group_acl.8

CLEANFILES += ext_wbinfo_group_acl.8 ext_wbinfo_group_acl
