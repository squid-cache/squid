#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2001/08/31 11:19:24 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS = digest_pw_auth
INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/

LDADD	= -L$(top_builddir)/lib -lmiscutil $(CRYPTLIB) $(XTRA_LIBS) $(SSLLIB)
