#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2003/01/23 00:35:54 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS = digest_pw_auth
INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/

LDADD	= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS) $(SSLLIB)
