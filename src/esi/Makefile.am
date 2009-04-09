include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libesi.la

libesi_la_SOURCES = \
	Assign.cc \
	Assign.h \
	Attempt.h \
	Context.cc \
	Context.h \
	CustomParser.cc \
	CustomParser.h \
	Element.h \
	ElementList.h \
	Esi.cc \
	Esi.h \
	Except.h \
	ExpatParser.cc \
	ExpatParser.h \
	Expression.cc \
	Expression.h \
	Include.cc \
	Include.h \
	Literal.h \
	Libxml2Parser.cc \
	Libxml2Parser.h \
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

