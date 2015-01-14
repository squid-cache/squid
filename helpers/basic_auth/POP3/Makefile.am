## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_pop3_auth
man_MANS= basic_pop3_auth.8
EXTRA_DIST= \
	basic_pop3_auth.8 \
	basic_pop3_auth.pl.in \
	required.m4

basic_pop3_auth: basic_pop3_auth.pl.in
	$(subst_perlshell)

basic_pop3_auth.8: basic_pop3_auth
	pod2man basic_pop3_auth basic_pop3_auth.8

CLEANFILES += basic_pop3_auth basic_pop3_auth.8
