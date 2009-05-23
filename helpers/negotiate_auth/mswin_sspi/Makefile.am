#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS = mswin_negotiate_auth

mswin_negotiate_auth_SOURCES = libnegotiatessp.c negotiate_auth.c negotiate.h

LDADD		= -L$(top_builddir)/lib -lsspwin32 -ladvapi32 -lmiscutil $(XTRA_LIBS)

EXTRA_DIST = readme.txt
