## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

AM_CPPFLAGS += -I$(top_srcdir)/lib

noinst_LTLIBRARIES = libntlmauth.la

libntlmauth_la_SOURCES = \
	ntlmauth.cc \
	ntlmauth.h \
	support_bits.cci \
	support_endian.h
