#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2002/12/27 10:26:40 robertc Exp $
#

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = -Werror -Wall
AM_CXXFLAGS = -Werror -Wall

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src

EXTRA_PROGRAMS = membanger tcp-banger2

TESTS = refcount

LDADD = -L$(top_builddir)/lib -lmiscutil

check_PROGRAMS= refcount

refcount_SOURCES = refcount.cc

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
