include $(top_srcdir)/src/Common.am

DIST_SUBDIRS = ntlmauth profiler rfcnb smblib libTrie
EXTRA_DIST=

SUBDIRS = rfcnb smblib
if ENABLE_AUTH_NTLM
SUBDIRS += ntlmauth
endif
if USE_ESI
SUBDIRS += libTrie
endif
if ENABLE_XPROF_STATS
SUBDIRS += profiler
endif


install: all
install-strip: all

if ENABLE_WIN32SPECIFIC
LIBSSPWIN32=libsspwin32.la
else
LIBSSPWIN32=
EXTRA_LTLIBRARIES = \
	libsspwin32.la
endif

noinst_LTLIBRARIES = \
	libmiscencoding.la \
	libmisccontainers.la \
	libmiscutil.la \
	$(LIBSSPWIN32)

#
# dirent.c, encrypt.c and getopt.c are needed for native Windows support.
#
EXTRA_libmiscutil_la_SOURCES = \
	dirent.c \
	encrypt.c \
	getopt.c

libmiscencoding_la_SOURCES = \
	base64.c \
	charset.c \
	html_quote.c \
	md5.c \
	rfc1738.c \
	rfc2617.c \
	uudecode.c

libmisccontainers_la_SOURCES = \
	hash.cc

libmiscutil_la_SOURCES = \
	malloc_trace.cc \
	MemPool.cc \
	MemPoolChunked.cc \
	MemPoolMalloc.cc \
	getfullhostname.c \
	heap.c \
	iso3307.c \
	radix.c \
	rfc1035.c \
	rfc1123.c \
	rfc2671.c \
	rfc3596.c \
	$(SNPRINTFSOURCE) \
	Splay.cc \
	stub_memaccount.c \
	util.c \
	xusleep.c

# $(top_srcdir)/include/version.h should be a dependency
libsspwin32_la_SOURCES = \
	sspwin32.c

TESTS += tests/testAll

check_PROGRAMS += tests/testAll

tests_testAll_SOURCES= \
	tests/testArray.h \
	tests/testArray.cc \
	tests/testRFC1035.h \
	tests/testRFC1035.cc \
	tests/testRFC1738.h \
	tests/testRFC1738.cc \
	tests/testMain.cc

tests_testAll_LDADD= \
	$(SQUID_CPPUNIT_LA) $(SQUID_CPPUNIT_LIBS) \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB)

tests_testAll_LDFLAGS = $(LIBADD_DL)


## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/include/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1

TESTS += testHeaders
CLEANFILES += testHeaders
.PHONY: testHeaders
