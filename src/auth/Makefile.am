#  Makefile for authentication modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.6 2005/10/23 11:55:38 hno Exp $
#
AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

##DIST_SUBDIRS	= basic digest ntlm
##SUBDIRS		= @AUTH_MODULES@

EXTRA_LIBRARIES	= libbasic.a libdigest.a libntlm.a libnegotiate.a
noinst_LIBRARIES	= @AUTH_LIBS@

libbasic_a_SOURCES	= basic/auth_basic.cc basic/auth_basic.h
libdigest_a_SOURCES	= digest/auth_digest.cc digest/auth_digest.h
libntlm_a_SOURCES	= ntlm/auth_ntlm.cc ntlm/auth_ntlm.h
libnegotiate_a_SOURCES	= negotiate/auth_negotiate.cc negotiate/auth_negotiate.h negotiate/negotiateScheme.cc negotiate/negotiateScheme.h

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src
