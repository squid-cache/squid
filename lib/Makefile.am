## Process this file with automake to produce Makefile.in
#
#  $Id: Makefile.am,v 1.2 2001/10/29 08:45:18 robertc Exp $
#

if NEED_OWN_SNPRINTF
EXTRAMISC=snprintf.c
else
EXTRAMISC=
endif

EXTRA_LIBRARIES = libregex.a libdlmalloc.a
noinst_LIBRARIES = libmiscutil.a @LIBREGEX@ @LIBDLMALLOC@ libntlmauth.a
EXTRA_libmiscutil_a_SOURCES = snprintf.c
libmiscutil_a_SOURCES = rfc1123.c rfc1738.c rfc1035.c rfc2617.c util.c \
	getfullhostname.c base64.c uudecode.c splay.c safe_inet_addr.c \
	iso3307.c md5.c radix.c stub_memaccount.c Array.c \
	Stack.c hash.c heap.c html_quote.c $(EXTRAMISC)
libmiscutil_a_LIBADD = @LIBOBJS@
# $(top_srcdir)/include/version.h should be a dependency
libregex_a_SOURCES = GNUregex.c
libdlmalloc_a_SOURCES = dlmalloc.c
libntlmauth_a_SOURCES = ntlmauth.c
libntlmauth_a_LIBADD = @LIBOBJS@

INCLUDES	= -I$(top_builddir)/include -I$(top_srcdir)/include
