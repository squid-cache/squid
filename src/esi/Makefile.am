include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libesi.la

ESI_PARSER_SOURCES = \
	CustomParser.cc \
	CustomParser.h

if HAVE_LIBEXPAT
ESI_PARSER_SOURCES += \
	ExpatParser.cc \
	ExpatParser.h
endif

if HAVE_LIBXML2
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
	ElementList.h \
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

INCLUDES += \
	-I$(top_srcdir)/lib/libTrie/include \
	-I$(top_builddir)/lib/libTrie/include

