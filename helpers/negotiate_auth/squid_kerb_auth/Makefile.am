#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2007/06/24 22:34:15 hno Exp $
#

libexec_PROGRAMS = squid_kerb_auth

SOURCE = squid_kerb_auth.c base64.c base64.h
EXTRA_DIST = readme.txt do.sh

squid_kerb_auth_SOURCES = $(SOURCE)

INCLUDES = -I$(top_srcdir)/include $(KERBINCS) -I.
#-I$(top_srcdir)/include -I$(top_srcdir)/src
LDADD = $(KERBLIBS)
#-L$(top_builddir)/lib -lmiscutil $(XTRA_LIBS)

# MIT
KERBINCS = @KRB5INCS@
KERBLIBS = @KRB5LIBS@

