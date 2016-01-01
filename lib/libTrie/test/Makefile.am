## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

AM_CPPFLAGS += -I$(top_srcdir)/include

TESTS += trie

check_PROGRAMS += trie

trie_SOURCES = trie.cc
trie_LDADD = $(top_builddir)/lib/libTrie/libTrie.a
