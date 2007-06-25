#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.6 2007/06/25 11:27:03 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS	= ncsa_auth
ncsa_auth_SOURCES	= ncsa_auth.c crypt_md5.c crypt_md5.h
man_MANS 		= ncsa_auth.8
EXTRA_DIST		= ncsa_auth.8
LDADD			= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS) $(SSLLIB)
INCLUDES      = -I$(top_srcdir)/include
