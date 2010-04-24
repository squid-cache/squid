#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 	= squid_ldap_auth
man_MANS 		= squid_ldap_auth.8
squid_ldap_auth_SOURCES	= squid_ldap_auth.c
EXTRA_DIST		= squid_ldap_auth.8 config.test

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(LIB_LDAP) \
	$(LIB_LBER) \
	$(XTRA_LIBS)

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)
