#
#  Makefile for the Squid SASL authentication helper
#
#  $Id: Makefile.am,v 1.5 2004/09/03 21:30:18 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

libexec_PROGRAMS	= sasl_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil $(LIBSASL) $(XTRA_LIBS)
EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
