#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2001/09/06 21:37:29 hno Exp $
#
#

libexec_PROGRAMS = yp_auth
yp_auth_SOURCES	= yp_auth.c nis_support.c
LDADD	= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS)
INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/
