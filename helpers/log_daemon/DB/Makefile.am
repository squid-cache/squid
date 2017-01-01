## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= log_db_daemon
CLEANFILES += log_db_daemon
EXTRA_DIST= \
	required.m4 \
	doc/views.sql \
	doc/date_day_column.sql \
	log_db_daemon.pl.in

log_db_daemon: log_db_daemon.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = log_db_daemon.8
CLEANFILES += log_db_daemon.8
EXTRA_DIST += log_db_daemon.8

log_db_daemon.8: log_db_daemon
	pod2man --section=8 log_db_daemon log_db_daemon.8

endif
