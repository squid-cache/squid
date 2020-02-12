## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = basic_fake_auth

basic_fake_auth_SOURCES = fake.cc
basic_fake_auth_LDADD = $(COMPAT_LIB)

EXTRA_DIST = required.m4
