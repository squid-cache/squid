#
#  Makefile for the Squid SASL authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

libexec_PROGRAMS	= sasl_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil $(LIBSASL) $(XTRA_LIBS)
EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
