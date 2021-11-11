## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libhttp2.la

libhttp2_la_SOURCES = \
	ErrorCode.cc \
	ErrorCode.h \
	forward.h \
	Frame.h \
	FrameParser.cc \
	FrameParser.h \
	FrameType.cc \
	FrameType.h \
	HpackHuffmanDecoder.cc \
	HpackHuffmanDecoder.h \
	HpackTables.cc \
	HpackTables.h \
	Settings.cc \
	Settings.h \
	StreamContext.cc \
	StreamContext.h \
	StreamState.cc \
	StreamState.h

FrameType.cc: FrameType.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk sbuf=1 < $(srcdir)/FrameType.h >$@) || ($(RM) -f $@ && exit 1)

StreamState.cc: StreamState.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk sbuf=1 < $(srcdir)/StreamState.h >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += FrameType.cc StreamState.cc
