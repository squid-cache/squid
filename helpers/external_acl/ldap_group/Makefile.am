#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 		= squid_ldap_group
man_MANS 			= squid_ldap_group.8
EXTRA_DIST			= squid_ldap_group.8
squid_ldap_group_SOURCES	= squid_ldap_group.c

INCLUDES = \
	-I$(top_srcdir) \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(LIB_LDAP) \
	$(LIB_LBER) \
	@XTRA_LIBS@
