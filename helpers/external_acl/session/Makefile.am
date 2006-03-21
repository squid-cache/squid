#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.2 2006/03/20 23:03:16 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 		= squid_session
man_MANS 			= squid_session.8
EXTRA_DIST			= squid_session.8
squid_session_SOURCES		= squid_session.c

LDADD		= $(LIBDB}
INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include
