#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 	= squid_radius_auth
man_MANS 		= squid_radius_auth.8
EXTRA_DIST		= squid_radius_auth.8 config.test
squid_radius_auth_SOURCES = \
			squid_rad_auth.c \
			radius.h \
			radius-util.c \
			radius-util.h

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(SSLLIB) \
	$(XTRA_LIBS)
