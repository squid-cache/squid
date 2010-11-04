include $(top_srcdir)/src/Common.am

# SAMBAPREFIX must point to the directory where Samba has been installed.
# By default, Samba is installed in /usr/local/samba. If you changed this
# by using the --prefix option when configuring Samba, you need to change
# SAMBAPREFIX accordingly.

## FIXME: autoconf should test for the samba path.

SMB_AUTH_HELPER	= basic_smb_auth.sh
SAMBAPREFIX=/usr/local/samba
SMB_AUTH_HELPER_PATH = $(libexecdir)/$(SMB_AUTH_HELPER)

libexec_SCRIPTS	= $(SMB_AUTH_HELPER)

libexec_PROGRAMS = basic_smb_auth
basic_smb_auth_SOURCES= basic_smb_auth.cc
basic_smb_auth_CXXFLAGS = -DSAMBAPREFIX=\"$(SAMBAPREFIX)\" -DHELPERSCRIPT=\"$(SMB_AUTH_HELPER_PATH)\"
basic_smb_auth_LDADD = \
		$(top_builddir)/lib/libmiscencoding.la \
		$(COMPAT_LIB) \
		$(XTRA_LIBS)

EXTRA_DIST = basic_smb_auth.sh COPYING-2.0 config.test
