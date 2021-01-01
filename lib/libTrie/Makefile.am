## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

DIST_SUBDIRS = . test
SUBDIRS = . test

noinst_LIBRARIES = libTrie.a

noinst_HEADERS = Trie.h TrieNode.h TrieCharTransform.h

libTrie_a_SOURCES = Trie.cc \
	Trie.h \
	TrieNode.cc \
	TrieNode.h \
	TrieCharTransform.h
