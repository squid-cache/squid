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

EXTRA_DIST = basic_smb_auth.sh COPYING-2.0 config.test
