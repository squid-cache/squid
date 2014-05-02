include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

DIST_SUBDIRS = test
SUBDIRS = test

noinst_LIBRARIES = libTrie.a

noinst_HEADERS = Trie.h TrieNode.h TrieCharTransform.h

libTrie_a_SOURCES = Trie.cc \
	Trie.cci \
	Trie.h \
	TrieNode.cc \
	TrieNode.cci \
	TrieNode.h \
	TrieCharTransform.h
