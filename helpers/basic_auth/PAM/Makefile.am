#
#  Makefile for the Squid PAM authentication helper
#
#  $Id: Makefile.am,v 1.4 2002/08/12 01:11:50 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

man_MANS		= pam_auth.8
EXTRA_DIST		= pam_auth.8
libexec_PROGRAMS	= pam_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil -lpam $(XTRA_LIBS)
