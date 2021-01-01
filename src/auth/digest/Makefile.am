## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

DIST_SUBDIRS= eDirectory file LDAP
SUBDIRS= $(DIGEST_AUTH_HELPERS)
EXTRA_DIST= helpers.m4

noinst_LTLIBRARIES= libdigest.la

libdigest_la_SOURCES= \
	Config.cc \
	Config.h \
	Scheme.cc \
	Scheme.h \
	User.cc \
	User.h \
	UserRequest.cc \
	UserRequest.h
