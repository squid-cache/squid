#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id$
#

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

AUTOMAKE_OPTIONS = subdir-objects

# No recursion is needed for the subdirs, we build from here. // @REPL_POLICIES@

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = @REPL_LIBS@

liblru_a_SOURCES = lru/store_repl_lru.cc
libheap_a_SOURCES = heap/store_heap_replacement.h heap/store_heap_replacement.cc heap/store_repl_heap.cc

## Until such time as we have a makefile in src/repl/heap etc.
check_PROGRAMS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/repl/heap/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "heap" || exit 1
## ./ has no .h files.
## ./lru/ has no .h files.

CLEANFILES += testHeaders
.PHONY: testHeaders
