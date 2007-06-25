#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.1 2007/06/25 11:02:35 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 	= squid_radius_auth
man_MANS 		= squid_radius_auth.8
EXTRA_DIST		= squid_radius_auth.8
squid_radius_auth_SOURCES = \
			squid_rad_auth.c \
			md5.c md5.h \
			radius.h \
			util.c util.h

LDADD = $(XTRA_LIBS)
