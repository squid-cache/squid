include $(top_srcdir)/src/Common.am

INCLUDES += -I$(top_srcdir)/include

# TESTS = trie trie-c
TESTS += trie

# check_PROGRAMS = trie trie-c
check_PROGRAMS += trie

trie_SOURCES = trie.cc
trie_LDADD = $(top_builddir)/lib/libTrie/libTrie.a

#trie_c_SOURCES = trie-c.c
#trie_c_LDADD = $(top_builddir)/lib/libTrie/libTrie.a -lm
