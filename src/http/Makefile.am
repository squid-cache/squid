## Copyright (C) 1996-2014 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = one
DIST_SUBDIRS = one

noinst_LTLIBRARIES = libsquid-http.la

libsquid_http_la_SOURCES = \
	forward.h \
	MethodType.cc \
	MethodType.h \
	ProtocolVersion.h \
	RegisteredHeaders.h \
	RequestMethod.cc \
	RequestMethod.h \
	StatusCode.cc \
	StatusCode.h \
	StatusLine.cc \
	StatusLine.h

libsquid_http_la_LIBADD= one/libhttp1.la

MethodType.cc: MethodType.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk sbuf=1 < $(srcdir)/MethodType.h | \
		sed -e 's%METHOD_%%' -e 's%_C%-C%' >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += MethodType.cc
