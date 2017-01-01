## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= basic_msnt_multi_domain_auth
man_MANS= basic_msnt_multi_domain_auth.8
EXTRA_DIST= \
	basic_msnt_multi_domain_auth.8 \
	basic_msnt_multi_domain_auth.pl.in \
	required.m4

basic_msnt_multi_domain_auth: basic_msnt_multi_domain_auth.pl.in
	$(subst_perlshell)

basic_msnt_multi_domain_auth.8: basic_msnt_multi_domain_auth
	pod2man basic_msnt_multi_domain_auth basic_msnt_multi_domain_auth.8

CLEANFILES += basic_msnt_multi_domain_auth basic_msnt_multi_domain_auth.8
