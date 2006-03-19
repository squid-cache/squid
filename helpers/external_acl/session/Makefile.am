#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.1 2006/03/19 01:11:44 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 		= squid_session
man_MANS 			= squid_session.8
EXTRA_DIST			= squid_session.8
squid_session_SOURCES		= squid_session.c

LDADD		= -ldb
INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include
