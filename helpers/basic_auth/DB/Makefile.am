## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_db_auth
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

CLEANFILES += basic_db_auth basic_db_auth.8
