#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.4 2002/10/19 01:00:27 robertc Exp $
#

AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = -Werror -Wall
AM_CXXFLAGS = -Werror -Wall

# No recursion is needed for the subdirs, we build from here. // @REPL_POLICIES@

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = @REPL_LIBS@

liblru_a_SOURCES = lru/store_repl_lru.cc
libheap_a_SOURCES = heap/store_heap_replacement.h heap/store_heap_replacement.cc heap/store_repl_heap.cc

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src/

