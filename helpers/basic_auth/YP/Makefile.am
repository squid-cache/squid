#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.4 2002/08/12 01:11:55 hno Exp $
#
#

libexec_PROGRAMS = yp_auth
yp_auth_SOURCES	= yp_auth.c nis_support.h nis_support.c
LDADD	= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS)
INCLUDES	= -I$(top_srcdir)/include
