## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

LDADD = \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/src/globals.o \
	$(top_builddir)/src/time.o \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

EXTRA_PROGRAMS = mem_node_test membanger splay tcp-banger2

EXTRA_DIST = \
	$(srcdir)/squidconf/* \
	testheaders.sh

ESI_ALL_TESTS = \
	ESIExpressions

if USE_ESI
  ESI_TESTS = $(ESI_ALL_TESTS)
else
  ESI_TESTS = 
endif

## Sort by dependencies - test lowest layers first
TESTS += debug \
	syntheticoperators \
	VirtualDeleteOperator \
	splay\
	MemPoolTest\
	mem_node_test\
	mem_hdr_test\
	$(ESI_TESTS) \
	squid-conf-tests

## Sort by alpha - any build failures are significant.
check_PROGRAMS += debug \
		$(ESI_TESTS) \
		MemPoolTest\
		mem_node_test\
		mem_hdr_test \
		splay \
		syntheticoperators \
		VirtualDeleteOperator


tcp_banger2_LDADD = $(top_builddir)/lib/libmiscutil.la

STUBS = stub_cbdata.cc stub_debug.cc stub_MemBuf.cc stub_SBuf.cc stub_tools.cc stub_fatal.cc
DEBUG_SOURCE = test_tools.cc $(STUBS)
CLEANFILES += $(STUBS)

stub_cbdata.cc: $(top_srcdir)/src/tests/stub_cbdata.cc
	cp $(top_srcdir)/src/tests/stub_cbdata.cc .

stub_debug.cc: $(top_srcdir)/src/tests/stub_debug.cc
	cp $(top_srcdir)/src/tests/stub_debug.cc .

stub_MemBuf.cc: $(top_srcdir)/src/tests/stub_MemBuf.cc
	cp $(top_srcdir)/src/tests/stub_MemBuf.cc .

stub_SBuf.cc: $(top_srcdir)/src/tests/stub_SBuf.cc
	cp $(top_srcdir)/src/tests/stub_SBuf.cc .

stub_tools.cc: $(top_srcdir)/src/tests/stub_tools.cc
	cp $(top_srcdir)/src/tests/stub_tools.cc .

stub_fatal.cc: $(top_srcdir)/src/tests/stub_fatal.cc
	cp $(top_srcdir)/src/tests/stub_fatal.cc .

## XXX: somewhat broken. Its meant to test our debugs() implementation.
## but it has never been linked to the actual src/debug.cc implementation !!
## all it tests are the stream operators and macro in src/Debug.h
debug_SOURCES = debug.cc $(DEBUG_SOURCE)

ESIExpressions_SOURCES = ESIExpressions.cc $(DEBUG_SOURCE)
ESIExpressions_LDADD = $(top_builddir)/src/esi/Expression.o \
		$(LDADD)

mem_node_test_SOURCES = mem_node_test.cc $(DEBUG_SOURCE)
mem_node_test_LDADD = $(top_builddir)/src/mem_node.o $(LDADD)

mem_hdr_test_SOURCES = mem_hdr_test.cc $(DEBUG_SOURCE)
mem_hdr_test_LDADD = \
	$(top_builddir)/src/stmem.o \
	$(top_builddir)/src/mem_node.o \
	$(LDADD)

MemPoolTest_SOURCES = MemPoolTest.cc $(DEBUG_SOURCE)

splay_SOURCES = splay.cc $(DEBUG_SOURCE)

syntheticoperators_SOURCES = syntheticoperators.cc $(DEBUG_SOURCE)

VirtualDeleteOperator_SOURCES = VirtualDeleteOperator.cc $(DEBUG_SOURCE)

## membanger won't link today. Bitrot..
##CC	= gcc
##CFLAGS	= -g -Wall -I../include -I../src
##OBJS	= membanger.o hash.o SizeToPool.o
##LIB	= -L. -lMem
##TARGLIB = libMem.a
##LIBOBJS = Mem.o \
##          Stack.o
##AR_R      = /usr/bin/ar r
##RM      = rm
##XTRA_LIBS = -lm  -lmalloc
##
##all:  membanger
##
##membanger: $(OBJS) $(TARGLIB)
##	$(CC) -o membanger $(OBJS) $(LIB)
##
##$(TARGLIB): $(LIBOBJS)
##	$(AR_R) $(TARGLIB) $(LIBOBJS)

squid-conf-tests: $(top_builddir)/src/squid.conf.default $(srcdir)/squidconf/*
	@failed=0; cfglist="$?"; rm -f $@ || $(TRUE); \
	for cfg in $$cfglist ; do \
		$(top_builddir)/src/squid -k parse -f $$cfg || \
			{ echo "FAIL: squid.conf test: $$cfg" | \
				sed s%$(top_builddir)/src/%% | \
				sed s%$(srcdir)/squidconf/%% ; \
				failed=1; break; \
			}; \
		if test "$$failed" -eq 0; then \
			echo "PASS: squid.conf test: $$cfg" | \
				sed s%$(top_builddir)/src/%% | \
				sed s%$(srcdir)/squidconf/%% ; \
		else break; fi; \
	done; \
	if test "$$failed" -eq 0; then cp $(TRUE) $@ ; fi

CLEANFILES += squid-conf-tests
