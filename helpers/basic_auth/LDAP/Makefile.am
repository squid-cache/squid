#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.6 2005/03/19 15:24:07 serassio Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 	= squid_ldap_auth
man_MANS 		= squid_ldap_auth.8
EXTRA_DIST		= squid_ldap_auth.8
squid_ldap_auth_SOURCES	= squid_ldap_auth.c

LDADD = -L$(top_builddir)/lib -lmiscutil $(LIB_LDAP) $(LIB_LBER) $(XTRA_LIBS)
INCLUDES      = -I$(top_srcdir)/include
