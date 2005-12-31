#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.6 2005/12/30 23:21:46 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS = digest_pw_auth
digest_pw_auth_SOURCES = digest_pw_auth.c \
	digest_common.h \
	text_backend.c \
	text_backend.h
INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/

LDADD	= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS) $(SSLLIB)
