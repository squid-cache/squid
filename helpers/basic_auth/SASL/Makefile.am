#
#  Makefile for the Squid SASL authentication helper
#
#  $Id: Makefile.am,v 1.2 2002/04/14 22:24:03 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/

libexec_PROGRAMS	= sasl_auth
LDADD			= -lsasl $(XTRA_LIBS)
EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
