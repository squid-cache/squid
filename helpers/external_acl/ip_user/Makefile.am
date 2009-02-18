#
#  Makefile for the ip_user external_acl helper by Rodrigo Campos
#
#  $Id$
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

INCLUDES = \
	-I$(top_srcdir) \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	@XTRA_LIBS@
