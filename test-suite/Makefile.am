#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.8 2003/06/24 12:31:00 robertc Exp $
#

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src

EXTRA_PROGRAMS = mem_node_test membanger splay tcp-banger2 rfc1738

## Sort by dependencies - test lowest layers first
TESTS = rfc1738 \
	refcount\
	splay\
	MemPoolTest\
	mem_node_test\
	mem_hdr_test\
	http_range_test

## Sort by alpha - any build failures are significant.
check_PROGRAMS= http_range_test \
		MemPoolTest\
		mem_node_test\
		mem_hdr_test \
		refcount\
		rfc1738\
		splay

LDADD = -L$(top_builddir)/lib -lmiscutil
mem_node_test_SOURCES = mem_node_test.cc
mem_node_test_LDADD = $(top_builddir)/src/mem_node.o $(LDADD)
mem_hdr_test_SOURCES = mem_hdr_test.cc test_tools.cc
mem_hdr_test_LDADD = $(top_builddir)/src/stmem.o \
		     $(top_builddir)/src/mem_node.o $(LDADD)
MemPoolTest_SOURCES = MemPoolTest.cc
refcount_SOURCES = refcount.cc

DEBUG_OBJECTS = $(top_builddir)/src/debug.o\
		$(top_builddir)/src/globals.o

http_range_test_SOURCES = http_range_test.cc
http_range_test_LDADD = $(top_builddir)/src/HttpHdrRange.o \
		$(top_builddir)/src/HttpHeaderTools.o \
		$(top_builddir)/src/MemBuf.o \
		$(top_builddir)/src/Packer.o \
		$(top_builddir)/src/String.o \
		$(top_builddir)/src/mem.o \
		$(DEBUG_OBJECTS) $(LDADD)

splay_SOURCES = splay.cc

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
