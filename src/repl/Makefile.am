#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id$
#

AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
CLEANFILES = 

# No recursion is needed for the subdirs, we build from here. // @REPL_POLICIES@

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = @REPL_LIBS@

liblru_a_SOURCES = lru/store_repl_lru.cc
libheap_a_SOURCES = heap/store_heap_replacement.h heap/store_heap_replacement.cc heap/store_repl_heap.cc

INCLUDES = \
	-I$(top_srcdir) \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src

check_PROGRAMS= testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/repl/heap/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "heap" || exit 1
## ./ has no .h files.
## ./lru/ has no .h files.

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
