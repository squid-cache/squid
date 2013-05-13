include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_db_auth
CLEANFILES += basic_db_auth basic_db_auth.8
man_MANS = basic_db_auth.8
EXTRA_DIST= \
	basic_db_auth.8 \
	passwd.sql \
	basic_db_auth.pl.in \
	required.m4

basic_db_auth.8: basic_db_auth
	pod2man basic_db_auth basic_db_auth.8

basic_db_auth: basic_db_auth.pl.in
	$(subst_perlshell)
