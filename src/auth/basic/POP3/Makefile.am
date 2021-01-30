## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_pop3_auth
CLEANFILES += basic_pop3_auth
EXTRA_DIST= \
	basic_pop3_auth.pl.in \
	required.m4

basic_pop3_auth: basic_pop3_auth.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = basic_pop3_auth.8
CLEANFILES += basic_pop3_auth.8
EXTRA_DIST += basic_pop3_auth.8

basic_pop3_auth.8: basic_pop3_auth
	pod2man --section=8 basic_pop3_auth basic_pop3_auth.8

endif
