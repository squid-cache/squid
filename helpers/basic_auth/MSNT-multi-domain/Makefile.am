include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_msnt_multi_domain_auth
EXTRA_DIST = basic_msnt_multi_domain_auth.pl.in README.txt required.m4
CLEANFILES += basic_msnt_multi_domain_auth

basic_msnt_multi_domain_auth: basic_msnt_multi_domain_auth.pl.in
	$(subst_perlshell)
