#
#  Makefile for the ip_user external_acl helper by Rodrigo Campos
#
#  $Id: Makefile.am,v 1.2 2002/07/22 00:38:14 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#


libexec_PROGRAMS = ip_user_check

ip_user_check_SOURCES = \
	dict.c \
	ip_user.h \
	main.c \
	match.c


EXTRA_DIST = \
	example.conf \
	example-deny_all_but.conf \
	license \
	README

# sysconf_DATA = 

LDADD	= @XTRA_LIBS@

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/
