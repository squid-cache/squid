#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.3 2003/01/23 00:35:30 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS	= ncsa_auth
ncsa_auth_SOURCES	= ncsa_auth.c
LDADD			= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS)
INCLUDES      = -I$(top_srcdir)/include
