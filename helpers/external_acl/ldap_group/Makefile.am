#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.4 2003/01/23 00:36:05 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 	= squid_ldap_group
man_MANS 		= squid_ldap_group.8
EXTRA_DIST		= squid_ldap_group.8
squid_ldap_group_SOURCES	= squid_ldap_group.c

LDADD = -lldap -llber $(XTRA_LIBS)
