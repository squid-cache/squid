#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.3 2002/05/20 02:03:56 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

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

LDADD	= $(XTRA_LIBS)

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/
