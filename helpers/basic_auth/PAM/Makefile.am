#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2001/08/31 11:19:17 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/

libexec_PROGRAMS	= pam_auth
LDADD			= -lpam $(XTRA_LIBS)
