#  Makefile for authentication modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2001/08/31 11:19:13 robertc Exp $
#
AUTOMAKE_OPTIONS = subdir-objects

DIST_SUBDIRS	= basic digest ntlm
SUBDIRS		= @AUTH_MODULES@

EXTRA_LIBRARIES	= libbasic.a libdigest.a libntlm.a
noinst_LIBRARIES	= @AUTH_LIBS@

libbasic_a_SOURCES	= basic/auth_basic.c basic/auth_basic.h
libdigest_a_SOURCES	= digest/auth_digest.c digest/auth_digest.h
libntlm_a_SOURCES	= ntlm/auth_ntlm.c ntlm/auth_ntlm.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src/
