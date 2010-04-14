#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS = digest_pw_auth
digest_pw_auth_SOURCES = digest_pw_auth.c \
	digest_common.h \
	text_backend.c \
	text_backend.h

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(CRYPTLIB) \
	$(XTRA_LIBS) \
	$(SSLLIB)

EXTRA_DIST = config.test
