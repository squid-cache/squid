include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= log_db_daemon
CLEANFILES += log_db_daemon log_db_daemon.8
man_MANS = log_db_daemon.8
EXTRA_DIST= \
	required.m4 \
	doc/views.sql \
	doc/date_day_column.sql \
	log_db_daemon.8 \
	log_db_daemon.pl.in

log_db_daemon.8: log_db_daemon
	pod2man log_db_daemon log_db_daemon.8

log_db_daemon: log_db_daemon.pl.in
	$(subst_perlshell)
