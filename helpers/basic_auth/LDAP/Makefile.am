#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.3 2002/01/08 16:24:15 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 	= squid_ldap_auth
man_MANS 		= squid_ldap_auth.8
EXTRA_DIST		= squid_ldap_auth.8
squid_ldap_auth_SOURCES	= squid_ldap_auth.c

LDADD = -lldap -llber
