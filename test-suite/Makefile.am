#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(top_builddir)/src/globals.o \
	$(top_builddir)/src/time.o

EXTRA_PROGRAMS = mem_node_test membanger splay tcp-banger2

EXTRA_DIST = testheaders.sh

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
	StackTest \
	refcount\
	splay\
	MemPoolTest\
	mem_node_test\
	mem_hdr_test\
	$(ESI_TESTS)

## Sort by alpha - any build failures are significant.
check_PROGRAMS += debug \
		$(ESI_TESTS) \
		MemPoolTest\
		mem_node_test\
		mem_hdr_test \
		refcount\
		splay \
		StackTest \
		syntheticoperators \
		VirtualDeleteOperator


tcp_banger2_LDADD = -L$(top_builddir)/lib -lmiscutil
DEBUG_SOURCE = test_tools.cc
debug_SOURCES = debug.cc $(DEBUG_SOURCE)
ESIExpressions_SOURCES = ESIExpressions.cc $(DEBUG_SOURCE)
ESIExpressions_LDADD = $(top_builddir)/src/esi/Expression.o \
		$(LDADD)
mem_node_test_SOURCES = mem_node_test.cc
mem_node_test_LDADD = $(top_builddir)/src/mem_node.o $(LDADD)
mem_hdr_test_SOURCES = mem_hdr_test.cc $(DEBUG_SOURCE)
mem_hdr_test_LDADD = $(top_builddir)/src/stmem.o \
		     $(top_builddir)/src/mem_node.o $(LDADD)
MemPoolTest_SOURCES = MemPoolTest.cc
refcount_SOURCES = refcount.cc

splay_SOURCES = splay.cc

StackTest_SOURCES = StackTest.cc $(DEBUG_SOURCE)
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
