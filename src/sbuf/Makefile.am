## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsbuf.la

libsbuf_la_SOURCES = \
	Algorithms.cc \
	Algorithms.h \
	List.cc \
	List.h \
	MemBlob.cc \
	MemBlob.h \
	SBuf.cc \
	SBuf.h \
	Stats.cc \
	Stats.h \
	Stream.h \
	forward.h

libsbuf_la_LIBADD = \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/src/debug/libdebug.la
