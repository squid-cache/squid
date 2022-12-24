## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= storeid_file_rewrite
CLEANFILES += storeid_file_rewrite
EXTRA_DIST= \
	storeid_file_rewrite.pl.in \
	required.m4

storeid_file_rewrite: storeid_file_rewrite.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = storeid_file_rewrite.8
CLEANFILES += storeid_file_rewrite.8
EXTRA_DIST += storeid_file_rewrite.8

storeid_file_rewrite.8: storeid_file_rewrite
	pod2man --section=8 storeid_file_rewrite storeid_file_rewrite.8

endif
