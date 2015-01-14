## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

AUTOMAKE_OPTIONS = subdir-objects

# No recursion is needed for the subdirs, we build from here.

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = $(REPL_LIBS)

liblru_a_SOURCES = lru/store_repl_lru.cc
libheap_a_SOURCES = heap/store_heap_replacement.h heap/store_heap_replacement.cc heap/store_repl_heap.cc


## Until such time as we have a makefile in src/repl/heap etc.
TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/heap/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1
## ./ has no .h files.
## ./lru/ has no .h files.

CLEANFILES += testHeaders
.PHONY: testHeaders
