## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libesi.la

ESI_PARSER_SOURCES =

if ENABLE_LIBEXPAT
ESI_PARSER_SOURCES += \
	ExpatParser.cc \
	ExpatParser.h
endif

if ENABLE_LIBXML2
ESI_PARSER_SOURCES += \
	Libxml2Parser.cc \
	Libxml2Parser.h
endif

libesi_la_SOURCES = \
	Assign.cc \
	Assign.h \
	Attempt.h \
	Context.cc \
	Context.h \
	$(ESI_PARSER_SOURCES) \
	Element.h \
	Esi.cc \
	Esi.h \
	Except.h \
	Expression.cc \
	Expression.h \
	Include.cc \
	Include.h \
	Literal.h \
	Module.cc \
	Module.h \
	Parser.cc \
	Parser.h \
	Segment.cc \
	Segment.h \
	Sequence.cc \
	Sequence.h \
	Var.h \
	VarState.cc \
	VarState.h
