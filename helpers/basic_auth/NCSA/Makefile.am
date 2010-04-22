#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS	= ncsa_auth
ncsa_auth_SOURCES	= ncsa_auth.c crypt_md5.c crypt_md5.h
man_MANS 		= ncsa_auth.8
EXTRA_DIST		= ncsa_auth.8 config.test
LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(CRYPTLIB) \
	$(XTRA_LIBS) \
	$(SSLLIB)

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)
