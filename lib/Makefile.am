## Process this file with automake to produce Makefile.in
#
#  $Id: Makefile.am,v 1.17 2004/12/22 11:23:16 hno Exp $
#

DIST_SUBDIRS = libTrie cppunit-1.10.0
SUBDIRS= libTrie @SQUID_CPPUNIT_DIR@

install: all
install-strip: all

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

if ENABLE_XPROF_STATS
XPROF_STATS_SOURCE = Profiler.c
else
XPROF_STATS_SOURCE = 
endif

if NEED_OWN_SNPRINTF
SNPRINTFSOURCE=snprintf.c
else
SNPRINTFSOURCE=
endif
if NEED_OWN_MD5
MD5SOURCE=md5.c
else
MD5SOURCE=
endif

EXTRA_LIBRARIES = \
	libdlmalloc.a \
	libregex.a
noinst_LIBRARIES = \
	@LIBDLMALLOC@ \
	libmiscutil.a \
	libntlmauth.a \
	@LIBREGEX@
EXTRA_libmiscutil_a_SOURCES = \
	md5.c \
	Profiler.c \
	snprintf.c
libmiscutil_a_SOURCES = \
	MemPool.cc \
	base64.c \
	getfullhostname.c \
	hash.c \
	heap.c \
	html_quote.c \
	iso3307.c \
	$(MD5SOURCE) \
	radix.c \
	rfc1035.c \
	rfc1123.c \
	rfc1738.c \
	rfc2617.c \
	safe_inet_addr.c \
	$(SNPRINTFSOURCE) \
	Splay.cc \
	stub_memaccount.c \
	util.c \
	uudecode.c \
	$(XPROF_STATS_SOURCE)
libmiscutil_a_LIBADD = \
	libTrie/src/Trie.o \
	libTrie/src/TrieNode.o \
	@LIBOBJS@
# $(top_srcdir)/include/version.h should be a dependency
libregex_a_SOURCES = \
	GNUregex.c
libdlmalloc_a_SOURCES = \
	dlmalloc.c
libntlmauth_a_SOURCES = \
	ntlmauth.c
libntlmauth_a_LIBADD = \
	@LIBOBJS@

INCLUDES	= -I$(top_builddir)/include -I$(top_srcdir)/include @SQUID_CPPUNIT_INC@
##FIXME - set these in configure.in and reuse

TESTS=$(check_PROGRAMS)
check_PROGRAMS=tests/testAll

tests_testAll_SOURCES= tests/testArray.cc tests/testMain.cc  tests/testArray.h \
	$(XPROF_STATS_SOURCE) \
	util.c

tests_testAll_LDADD= @SQUID_CPPUNIT_LA@

tests_testAll_LDFLAGS = $(LIBADD_DL)
