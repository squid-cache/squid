## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

DIST_SUBDIRS= kerberos SSPI wrapper
SUBDIRS= $(NEGOTIATE_AUTH_HELPERS)
EXTRA_DIST= helpers.m4

noinst_LTLIBRARIES = libnegotiate.la

libnegotiate_la_SOURCES = \
	Scheme.cc \
	Scheme.h \
	Config.cc \
	Config.h \
	User.cc \
	User.h \
	UserRequest.cc \
	UserRequest.h
