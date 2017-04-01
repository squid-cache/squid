## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= ext_session_acl
man_MANS= ext_session_acl.8

ext_session_acl_SOURCES= \
	ext_session_acl.cc
ext_session_acl_LDADD = \
	$(COMPAT_LIB) \
	-ldb

EXTRA_DIST= ext_session_acl.8 required.m4
