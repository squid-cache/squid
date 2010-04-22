#
#  Makefile for the Squid SASL authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS	= sasl_auth

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(LIBSASL) \
	$(XTRA_LIBS)

EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf config.test
