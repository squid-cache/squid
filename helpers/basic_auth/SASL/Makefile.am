#
#  Makefile for the Squid SASL authentication helper
#
#  $Id: Makefile.am,v 1.4 2003/01/23 00:35:37 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

libexec_PROGRAMS	= sasl_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil -lsasl $(XTRA_LIBS)
EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
