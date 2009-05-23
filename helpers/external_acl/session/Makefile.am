#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS 		= squid_session
man_MANS 			= squid_session.8
EXTRA_DIST			= squid_session.8
squid_session_SOURCES		= squid_session.c

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	@LIB_DB@
