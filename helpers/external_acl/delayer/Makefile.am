## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS = ext_delayer_acl
CLEANFILES += ext_delayer_acl
EXTRA_DIST= \
	required.m4 \
	ext_delayer_acl.pl.in

ext_delayer_acl: ext_delayer_acl.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = ext_delayer_acl.8
CLEANFILES += ext_delayer_acl.8
EXTRA_DIST += ext_delayer_acl.8

ext_delayer_acl.8: ext_delayer_acl
	pod2man --section=8 ext_delayer_acl ext_delayer_acl.8

endif
