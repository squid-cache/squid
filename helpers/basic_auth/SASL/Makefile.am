#
#  Makefile for the Squid SASL authentication helper
#
#  $Id: Makefile.am,v 1.7 2004/12/20 16:30:15 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

libexec_PROGRAMS	= sasl_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil $(LIBSASL) $(XTRA_LIBS)
EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
