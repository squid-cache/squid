INCLUDES = -I$(top_srcdir)/include

TESTS = trie trie-c

check_PROGRAMS = trie trie-c

trie_SOURCES = trie.cc
trie_LDADD = $(top_builddir)/src/libTrie.a

trie_c_SOURCES = trie-c.c
trie_c_LDADD = $(top_builddir)/src/libTrie.a -lstdc++

