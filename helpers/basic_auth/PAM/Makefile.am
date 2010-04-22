#
#  Makefile for the Squid PAM authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

man_MANS		= pam_auth.8
EXTRA_DIST		= pam_auth.8 config.test
libexec_PROGRAMS	= pam_auth

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	-lpam \
	$(XTRA_LIBS)
