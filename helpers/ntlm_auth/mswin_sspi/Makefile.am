#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2005/10/30 21:48:22 serassio Exp $
#

libexec_PROGRAMS = mswin_ntlm_auth

mswin_ntlm_auth_SOURCES = libntlmssp.c ntlm_auth.c ntlm.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src

LDADD		= -L$(top_builddir)/lib -lntlmauth -lsspwin32 -lnetapi32 \
		  -ladvapi32 -lmiscutil $(XTRA_LIBS)

EXTRA_DIST = readme.txt
