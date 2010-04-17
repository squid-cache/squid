include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_db_auth
CLEANFILES += basic_db_auth basic_db_auth.8
do_subst = sed -e 's,[@]PERL[@],$(PERL),g'
man_MANS = basic_db_auth.8
EXTRA_DIST= \
	basic_db_auth.8 \
	passwd.sql \
	basic_db_auth.in \
	config.test

basic_db_auth.8: basic_db_auth
	pod2man basic_db_auth basic_db_auth.8

basic_db_auth: basic_db_auth.in
	$(do_subst) < $(srcdir)/basic_db_auth.in  >basic_db_auth
