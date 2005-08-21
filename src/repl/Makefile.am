#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.7 2005/08/20 21:08:38 serassio Exp $
#

AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

# No recursion is needed for the subdirs, we build from here. // @REPL_POLICIES@

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = @REPL_LIBS@

liblru_a_SOURCES = lru/store_repl_lru.cc
libheap_a_SOURCES = heap/store_heap_replacement.h heap/store_heap_replacement.cc heap/store_repl_heap.cc

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src

