#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.4 2002/05/20 02:03:55 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#


libexec_PROGRAMS = msnt_auth

msnt_auth_SOURCES = md4.c rfcnb-io.c rfcnb-util.c session.c msntauth.c \
		msntauth.h smbdes.c smbencrypt.c smblib-util.c smblib.c \
		valid.c denyusers.c allowusers.c confload.c \
		byteorder.h rfcnb-common.h rfcnb-error.h rfcnb.h \
		rfcnb-io.h rfcnb-priv.h rfcnb-util.h smblib-common.h \
		smblib.h smblib-priv.h std-defines.h std-includes.h valid.h

EXTRA_DIST = \
	COPYING-2.0 \
	msntauth.conf \
	msntauth-v2.0.lsm \
	README.html

LDADD	= @XTRA_LIBS@

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/
