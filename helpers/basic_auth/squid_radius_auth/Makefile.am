#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.2 2007/11/20 14:34:17 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 	= squid_radius_auth
man_MANS 		= squid_radius_auth.8
EXTRA_DIST		= squid_radius_auth.8
squid_radius_auth_SOURCES = \
			squid_rad_auth.c \
			radius.h \
			radius-util.c \
			radius-util.h

LDADD			= -L$(top_builddir)/lib -lmiscutil $(SSLLIB) $(XTRA_LIBS)
INCLUDES		= -I$(top_srcdir)/include
