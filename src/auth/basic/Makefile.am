## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

DIST_SUBDIRS = \
        DB \
        fake \
        getpwnam \
        LDAP \
        NCSA \
        NIS \
        PAM \
        POP3 \
        RADIUS \
        SASL \
        SMB \
        SSPI

SUBDIRS = $(BASIC_AUTH_HELPERS)
EXTRA_DIST= helpers.m4

noinst_LTLIBRARIES = libbasic.la

libbasic_la_SOURCES = \
	Config.cc \
	Config.h \
	Scheme.cc \
	Scheme.h \
	User.cc \
	User.h \
	UserRequest.cc \
	UserRequest.h
