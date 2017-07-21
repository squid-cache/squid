## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

DIST_SUBDIRS =

SUBDIRS = $(BEARER_AUTH_HELPERS)
EXTRA_DIST= helpers.m4

noinst_LTLIBRARIES = libbearer.la

libbearer_la_SOURCES = \
	Config.cc \
	Config.h \
	forward.h \
	Scheme.cc \
	Scheme.h \
	Token.cc \
	Token.h \
	User.cc \
	User.h \
	UserRequest.cc \
	UserRequest.h
