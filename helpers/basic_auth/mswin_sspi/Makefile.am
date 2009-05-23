#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = mswin_auth

mswin_auth_SOURCES = mswin_auth.c valid.c valid.h

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	-lnetapi32 -ladvapi32 -lsspwin32 \
	$(XTRA_LIBS)

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

EXTRA_DIST = readme.txt
