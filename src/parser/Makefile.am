## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsquid-parser.la

libsquid_parser_la_SOURCES = \
	Tokenizer.h \
	Tokenizer.cc

SBUF_SOURCE= \
	$(top_srcdir)/src/base/CharacterSet.h \
	$(top_srcdir)/src/SBuf.h \
	$(top_srcdir)/src/SBuf.cc \
	$(top_srcdir)/src/MemBlob.h \
	$(top_srcdir)/src/MemBlob.cc \
	$(top_srcdir)/src/OutOfBoundsException.h \
	$(top_srcdir)/src/SBufExceptions.h \
	$(top_srcdir)/src/SBufExceptions.cc \
	$(top_srcdir)/src/String.cc \
	$(top_srcdir)/src/SquidString.h \
	$(top_srcdir)/src/base/TextException.h \
	$(top_srcdir)/src/base/TextException.cc

