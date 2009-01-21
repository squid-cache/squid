#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#

libexec_PROGRAMS = mswin_ntlm_auth

mswin_ntlm_auth_SOURCES = libntlmssp.c ntlm_auth.c ntlm.h

INCLUDES = \
	-I$(top_srcdir)/libsquid-compat \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

LDADD = \
	-L$(top_builddir)/libsquid-compat/libsquid-compat.la \
	-L$(top_builddir)/lib -lmiscutil -lntlmauth \
	-lsspwin32 \
	-lnetapi32 \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt
