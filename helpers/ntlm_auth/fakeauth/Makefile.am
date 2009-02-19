#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS = fakeauth_auth
fakeauth_auth_SOURCES	= fakeauth_auth.c ntlm.h

INCLUDES = \
	-I$(top_srcdir) \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(CRYPTLIB) \
	$(XTRA_LIBS)
