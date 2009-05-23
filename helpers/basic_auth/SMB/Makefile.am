#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

# SAMBAPREFIX must point to the directory where Samba has been installed.
# By default, Samba is installed in /usr/local/samba. If you changed this
# by using the --prefix option when configuring Samba, you need to change
# SAMBAPREFIX accordingly.

## FIXME: autoconf should test for the samba path.

SMB_AUTH_HELPER	= smb_auth.sh
SAMBAPREFIX=/usr/local/samba
SMB_AUTH_HELPER_PATH = $(libexecdir)/$(SMB_AUTH_HELPER)

libexec_SCRIPTS	= $(SMB_AUTH_HELPER)
libexec_PROGRAMS = smb_auth
smb_auth_CFLAGS = -DSAMBAPREFIX=\"$(SAMBAPREFIX)\" -DHELPERSCRIPT=\"$(SMB_AUTH_HELPER_PATH)\"
EXTRA_DIST = smb_auth.sh COPYING-2.0

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(XTRA_LIBS)
