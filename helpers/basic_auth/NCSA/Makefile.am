#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.5 2003/05/31 11:31:46 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS	= ncsa_auth
ncsa_auth_SOURCES	= ncsa_auth.c crypt_md5.c crypt_md5.h
LDADD			= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS) $(SSLLIB)
INCLUDES      = -I$(top_srcdir)/include
