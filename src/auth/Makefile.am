#  Makefile for authentication modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.3 2003/01/23 00:37:50 robertc Exp $
#
AUTOMAKE_OPTIONS = subdir-objects
AM_CXXFLAGS = -Werror -Wall

##DIST_SUBDIRS	= basic digest ntlm
##SUBDIRS		= @AUTH_MODULES@

EXTRA_LIBRARIES	= libbasic.a libdigest.a libntlm.a
noinst_LIBRARIES	= @AUTH_LIBS@

libbasic_a_SOURCES	= basic/auth_basic.cc basic/auth_basic.h
libdigest_a_SOURCES	= digest/auth_digest.cc digest/auth_digest.h
libntlm_a_SOURCES	= ntlm/auth_ntlm.cc ntlm/auth_ntlm.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src/
