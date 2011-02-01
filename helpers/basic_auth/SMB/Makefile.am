#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= smb_auth.sh
libexec_PROGRAMS = smb_auth
smb_auth_CFLAGS = -DHELPERSCRIPT=\"$(libexecdir)/smb_auth.sh\"
EXTRA_DIST = smb_auth.sh COPYING-2.0 config.test

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(XTRA_LIBS)
