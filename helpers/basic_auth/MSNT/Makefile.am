#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2001/08/31 11:19:16 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#


libexec_PROGRAMS = msnt_auth

msnt_auth_SOURCES = md4.c rfcnb-io.c rfcnb-util.c session.c msntauth.c \
		smbdes.c smbencrypt.c smblib-util.c smblib.c \
		valid.c denyusers.c allowusers.c confload.c

LDADD	= @XTRA_LIBS@

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/
