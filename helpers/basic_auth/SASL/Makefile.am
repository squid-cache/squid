#
#  Makefile for the Squid SASL authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS	= sasl_auth

INCLUDES = \
	-I$(top_srcdir)/libsquid-compat \
	-I$(top_srcdir)/include

LDADD = \
	-L$(top_builddir)/libsquid-compat/libsquid-compat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(LIBSASL) \
	$(XTRA_LIBS)

EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
