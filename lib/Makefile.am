## Process this file with automake to produce Makefile.in
#
#  $Id$
#

include $(top_srcdir)/src/Common.am

SUBDIRS =

if USE_LOADABLE_MODULES
SUBDIRS += libLtdl
endif

if USE_ESI
SUBDIRS += libTrie
endif


install: all
install-strip: all


if ENABLE_XPROF_STATS
XPROF_STATS_SOURCE = Profiler.c
else
XPROF_STATS_SOURCE = 
endif

if ENABLE_WIN32SPECIFIC
LIBSSPWIN32=libsspwin32.a
WIN32SRC = win32lib.c
else
LIBSSPWIN32=
WIN32SRC=
endif

EXTRA_LIBRARIES = \
	libsspwin32.a
noinst_LIBRARIES = \
	libmiscutil.a \
	libntlmauth.a \
	$(LIBSSPWIN32)

#
# dirent.c, encrypt.c and getopt.c are needed for native Windows support.
#
EXTRA_libmiscutil_a_SOURCES = \
	dirent.c \
	encrypt.c \
	getopt.c \
	md5.c \
	Profiler.c \
	win32lib.c
libmiscutil_a_SOURCES = \
	MemPool.cc \
	base64.c \
	charset.c \
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
	rfc3596.c \
	$(SNPRINTFSOURCE) \
	Splay.cc \
	strnstr.cc \
	stub_memaccount.c \
	util.c \
	uudecode.c \
	xusleep.c \
	$(XPROF_STATS_SOURCE) \
	$(WIN32SRC)
libmiscutil_a_LIBADD = @LIBOBJS@

# $(top_srcdir)/include/version.h should be a dependency
libntlmauth_a_SOURCES = \
	ntlmauth.c
libntlmauth_a_LIBADD = \
	@LIBOBJS@
libsspwin32_a_SOURCES = \
	base64.c \
	sspwin32.c
libsspwin32_a_LIBADD = \
	@LIBOBJS@


TESTS += tests/testAll

check_PROGRAMS += tests/testAll

tests_testAll_SOURCES= \
	tests/testArray.h \
	tests/testArray.cc \
	tests/testRFC1035.h \
	tests/testRFC1035.cc \
	tests/testMain.cc \
	$(XPROF_STATS_SOURCE) \
	$(WIN32SRC) \
	util.c

tests_testAll_LDADD= @SQUID_CPPUNIT_LA@ @SQUID_CPPUNIT_LIBS@

tests_testAll_LDFLAGS = $(LIBADD_DL)


## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/include/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/include" || exit 1

TESTS += testHeaders
CLEANFILES += testHeaders
.PHONY: testHeaders
