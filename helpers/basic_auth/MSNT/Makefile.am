#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2001/12/27 00:23:32 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#


libexec_PROGRAMS = msnt_auth

msnt_auth_SOURCES = md4.c rfcnb-io.c rfcnb-util.c session.c msntauth.c \
		smbdes.c smbencrypt.c smblib-util.c smblib.c \
		valid.c denyusers.c allowusers.c confload.c \
		byteorder.h rfcnb-common.h rfcnb-error.h rfcnb.h \
		rfcnb-io.h rfcnb-priv.h rfcnb-util.h smblib-common.h \
		smblib.h smblib-priv.h std-defines.h std-includes.h valid.h

LDADD	= @XTRA_LIBS@

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/
