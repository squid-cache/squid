## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

SUBDIRS = one url_rewriters
DIST_SUBDIRS = one url_rewriters

noinst_LTLIBRARIES = libhttp.la

libhttp_la_SOURCES = \
	ContentLengthInterpreter.cc \
	ContentLengthInterpreter.h \
	Message.cc \
	Message.h \
	MethodType.cc \
	MethodType.h \
	ProtocolVersion.h \
	RegisteredHeaders.cc \
	RegisteredHeaders.h \
	RegisteredHeadersHash.cci \
	RequestMethod.cc \
	RequestMethod.h \
	StateFlags.h \
	StatusCode.cc \
	StatusCode.h \
	StatusLine.cc \
	StatusLine.h \
	Stream.cc \
	Stream.h \
	forward.h

libhttp_la_LIBADD= one/libhttp1.la

MethodType.cc: MethodType.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk sbuf=1 < $(srcdir)/MethodType.h | \
		sed -e 's%METHOD_%%' -e 's%_C%-C%' >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += MethodType.cc

EXTRA_DIST = RegisteredHeadersHash.gperf
