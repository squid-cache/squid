## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

# C/C++ version of the helper (circa. 1996)
# libexec_PROGRAMS = url_lfs_rewrite
# url_lfs_rewrite_SOURCES = rredir.cc
# url_lfs_rewrite_LDADD = $(COMPAT_LIB)

# Perl helper
libexec_SCRIPTS = url_lfs_rewrite
CLEANFILES += url_lfs_rewrite
EXTRA_DIST= \
	required.m4 \
	url_lfs_rewrite.pl.in

url_lfs_rewrite: url_lfs_rewrite.pl.in
	$(subst_perlshell)

if ENABLE_POD2MAN_DOC
man_MANS = url_lfs_rewrite.8
CLEANFILES += url_lfs_rewrite.8
EXTRA_DIST += url_lfs_rewrite.8

url_lfs_rewrite.8: url_lfs_rewrite
	pod2man --section=8 url_lfs_rewrite url_lfs_rewrite.8

endif
