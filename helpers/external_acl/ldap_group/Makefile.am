#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.6 2005/03/19 15:24:07 serassio Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 		= squid_ldap_group
man_MANS 			= squid_ldap_group.8
EXTRA_DIST			= squid_ldap_group.8
squid_ldap_group_SOURCES	= squid_ldap_group.c

LDADD		= -L$(top_builddir)/lib -lmiscutil $(LIB_LDAP) $(LIB_LBER) @XTRA_LIBS@
INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include
