#
#  Makefile for the Squid PAM authentication helper
#
#  $Id: Makefile.am,v 1.7 2003/08/03 20:38:02 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

man_MANS		= pam_auth.8
EXTRA_DIST		= pam_auth.8
libexec_PROGRAMS	= pam_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil -lpam $(XTRA_LIBS)
