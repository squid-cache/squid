## Process this file with automake to produce Makefile.in
#
#  $Id: Makefile.am,v 1.5 2002/10/02 11:06:30 robertc Exp $
#

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
	MemPool.c \
	Array.c \
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
	splay.c \
	Stack.c \
	stub_memaccount.c \
	util.c \
	uudecode.c \
	$(XPROF_STATS_SOURCE)
libmiscutil_a_LIBADD = \
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

INCLUDES	= -I$(top_builddir)/include -I$(top_srcdir)/include
