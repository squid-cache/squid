#
#  Makefile for the Squid PAM authentication helper
#
#  $Id: Makefile.am,v 1.3 2002/01/08 16:24:21 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/

man_MANS		= pam_auth.8
EXTRA_DIST		= pam_auth.8
libexec_PROGRAMS	= pam_auth
LDADD			= -lpam $(XTRA_LIBS)
