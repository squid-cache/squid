## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

if !ENABLE_WIN32SPECIFIC
libexec_SCRIPTS	= basic_smb_auth.sh
libexec_PROGRAMS = basic_smb_auth
endif

basic_smb_auth_SOURCES= basic_smb_auth.cc
basic_smb_auth_CXXFLAGS = -DHELPERSCRIPT=\"$(libexecdir)/basic_smb_auth.sh\"
basic_smb_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

EXTRA_DIST= \
	basic_smb_auth.sh \
	required.m4
