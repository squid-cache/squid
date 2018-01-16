## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS = security_fake_certverify
CLEANFILES += security_fake_certverify
EXTRA_DIST= \
	security_fake_certverify.pl.in \
	required.m4

security_fake_certverify: security_fake_certverify.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = security_fake_certverify.8
CLEANFILES += security_fake_certverify.8
EXTRA_DIST += security_fake_certverify.8

security_fake_certverify.8: security_fake_certverify
	pod2man --section=8 security_fake_certverify security_fake_certverify.8

endif
