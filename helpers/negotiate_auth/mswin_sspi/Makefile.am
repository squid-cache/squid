#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2005/11/01 08:57:13 serassio Exp $
#

libexec_PROGRAMS = mswin_negotiate_auth

mswin_negotiate_auth_SOURCES = libnegotiatessp.c negotiate_auth.c negotiate.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src

LDADD		= -L$(top_builddir)/lib -lsspwin32 -ladvapi32 -lmiscutil $(XTRA_LIBS)

EXTRA_DIST = readme.txt
