## Process this file with automake to produce Makefile.in
#
#  $Id: Makefile.am,v 1.30 2007/12/04 13:22:54 hno Exp $
#

DIST_SUBDIRS = libTrie
SUBDIRS= libTrie

install: all
install-strip: all

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

if ENABLE_XPROF_STATS
XPROF_STATS_SOURCE = Profiler.c
else
XPROF_STATS_SOURCE = 
endif

if NEED_OWN_STRSEP
STRSEPSOURCE=strsep.c
else
STRSEPSOURCE=
endif
if NEED_OWN_STRTOLL
STRTOLLSOURCE=strtoll.c
else
STRTOLLSOURCE=
endif

if ENABLE_WIN32SPECIFIC
LIBSSPWIN32=libsspwin32.a
WIN32SRC = win32lib.c
else
LIBSSPWIN32=
WIN32SRC=
endif

EXTRA_LIBRARIES = \
	libregex.a \
	libsspwin32.a
noinst_LIBRARIES = \
	libmiscutil.a \
	libntlmauth.a \
	$(LIBSSPWIN32) \
	@LIBREGEX@
EXTRA_libmiscutil_a_SOURCES = \
	md5.c \
	Profiler.c \
	strsep.c \
	strtoll.c \
	win32lib.c
libmiscutil_a_SOURCES = \
	MemPool.cc \
	base64.c \
	getfullhostname.c \
	hash.c \
	heap.c \
	html_quote.c \
	iso3307.c \
	md5.c \
	radix.c \
	rfc1035.c \
	rfc1123.c \
	rfc1738.c \
	rfc2617.c \
	safe_inet_addr.c \
	$(SNPRINTFSOURCE) \
	Splay.cc \
	$(STRSEPSOURCE) \
	$(STRTOLLSOURCE) \
	stub_memaccount.c \
	util.c \
	uudecode.c \
	assert.c \
	xusleep.c \
	$(XPROF_STATS_SOURCE) \
	$(WIN32SRC)
libmiscutil_a_LIBADD = \
	libTrie/src/Trie.o \
	libTrie/src/TrieNode.o \
	@LIBOBJS@
# $(top_srcdir)/include/version.h should be a dependency
libregex_a_SOURCES = \
	GNUregex.c
libntlmauth_a_SOURCES = \
	ntlmauth.c
libntlmauth_a_LIBADD = \
	@LIBOBJS@
libsspwin32_a_SOURCES = \
	sspwin32.c

INCLUDES	= -I$(top_builddir)/include -I$(top_srcdir)/include @SQUID_CPPUNIT_INC@
##FIXME - set these in configure.in and reuse

TESTS=$(check_PROGRAMS)
check_PROGRAMS=tests/testAll

tests_testAll_SOURCES= tests/testArray.cc tests/testMain.cc  tests/testArray.h \
	$(XPROF_STATS_SOURCE) \
	$(WIN32SRC) \
	util.c assert.c

tests_testAll_LDADD= @SQUID_CPPUNIT_LA@ @SQUID_CPPUNIT_LIBS@

tests_testAll_LDFLAGS = $(LIBADD_DL)
