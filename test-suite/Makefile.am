#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.20 2007/01/04 20:52:57 hno Exp $
#

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src

EXTRA_PROGRAMS = mem_node_test membanger splay tcp-banger2 rfc1738

ESI_ALL_TESTS = \
	ESIExpressions

if USE_ESI
  ESI_TESTS = $(ESI_ALL_TESTS)
else
  ESI_TESTS = 
endif

## Sort by dependencies - test lowest layers first
TESTS = debug \
	syntheticoperators \
	VirtualDeleteOperator \
	StackTest \
	rfc1738 \
	refcount\
	splay\
	MemPoolTest\
	mem_node_test\
	mem_hdr_test\
	$(ESI_TESTS)

## Sort by alpha - any build failures are significant.
check_PROGRAMS= debug \
		$(ESI_TESTS) \
		MemPoolTest\
		mem_node_test\
		mem_hdr_test \
		refcount\
		rfc1738\
		splay \
		StackTest \
		syntheticoperators \
		VirtualDeleteOperator


LDADD =$(top_builddir)/src/globals.o $(top_builddir)/src/time.o -L$(top_builddir)/lib -lmiscutil
tcp_banger2_LDADD = -L$(top_builddir)/lib -lmiscutil
DEBUG_SOURCE = test_tools.cc
debug_SOURCES = debug.cc $(DEBUG_SOURCE)
ESIExpressions_SOURCES = ESIExpressions.cc $(DEBUG_SOURCE)
ESIExpressions_LDADD = $(top_builddir)/src/ESIExpression.o \
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

rfc1738_SOURCES = rfc1738.cc

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
