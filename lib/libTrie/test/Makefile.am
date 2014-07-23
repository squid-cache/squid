include $(top_srcdir)/src/Common.am

AM_CPPFLAGS += -I$(top_srcdir)/include

TESTS += trie

check_PROGRAMS += trie

trie_SOURCES = trie.cc
trie_LDADD = $(top_builddir)/lib/libTrie/libTrie.a
