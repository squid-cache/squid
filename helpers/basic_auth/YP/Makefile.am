#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#

libexec_PROGRAMS = yp_auth
yp_auth_SOURCES	= yp_auth.c nis_support.h nis_support.c

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include

LDADD = \
	-L$(top_builddir)/squid-compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(CRYPTLIB) \
	$(XTRA_LIBS)
