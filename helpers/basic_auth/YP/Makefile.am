#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.5 2003/01/23 00:35:44 robertc Exp $
#
#

libexec_PROGRAMS = yp_auth
yp_auth_SOURCES	= yp_auth.c nis_support.h nis_support.c
LDADD	= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS)
INCLUDES	= -I$(top_srcdir)/include
