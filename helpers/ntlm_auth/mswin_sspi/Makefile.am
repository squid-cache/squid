#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = mswin_ntlm_auth

mswin_ntlm_auth_SOURCES = libntlmssp.c ntlm_auth.c ntlm.h

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil -lntlmauth \
	-lsspwin32 \
	-lnetapi32 \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt
