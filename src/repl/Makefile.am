## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

# No recursion is needed for the subdirs, we build from here.

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = $(REPL_LIBS)

liblru_a_SOURCES = lru/store_repl_lru.cc
libheap_a_SOURCES = \
	heap/store_heap_replacement.cc \
	heap/store_heap_replacement.h \
	heap/store_repl_heap.cc

