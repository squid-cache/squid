## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
	forward.h \
	MethodType.cc \
	MethodType.h \
	ProtocolVersion.h \
	RegisteredHeaders.h \
	RegisteredHeaders.cc \
	RegisteredHeadersHash.cci \
	RequestMethod.cc \
	RequestMethod.h \
	StateFlags.h \
	StatusCode.cc \
	StatusCode.h \
	StatusLine.cc \
	StatusLine.h \
	Stream.cc \
	Stream.h

libhttp_la_LIBADD= one/libhttp1.la

MethodType.cc: MethodType.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk sbuf=1 < $(srcdir)/MethodType.h | \
		sed -e 's%METHOD_%%' -e 's%_C%-C%' >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += MethodType.cc

gperf-files: RegisteredHeadersHash.gperf
	if test $(srcdir)/RegisteredHeadersHash.gperf -nt $(srcdir)/RegisteredHeadersHash.cci; then gperf -m 100000 $(srcdir)/RegisteredHeadersHash.gperf | sed 's/register //g' > $(srcdir)/RegisteredHeadersHash.cci; fi

EXTRA_DIST = RegisteredHeadersHash.gperf

.PHONY: gperf-files
