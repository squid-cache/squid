include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_pop3_auth
EXTRA_DIST = basic_pop3_auth.pl.in config.test
CLEANFILES += basic_pop3_auth

basic_pop3_auth: basic_pop3_auth.pl.in
	$(subst_perlshell)
