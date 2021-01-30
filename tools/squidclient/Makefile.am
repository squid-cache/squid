## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

SUBDIRS =
EXTRA_DIST = squidclient.1
man_MANS = squidclient.1
DISTCLEANFILES =

LDADD = \
	$(top_builddir)/src/ip/libip.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(LIBGNUTLS_LIBS) \
	$(NETTLELIB) \
	$(KRB5LIBS) \
	$(XTRA_LIBS)

include $(top_srcdir)/doc/manuals/Substitute.am

## Several files need to be shared but we cannot depend on the other
## directories to be built.
test_tools.cc: $(top_srcdir)/test-suite/test_tools.cc
	cp $(top_srcdir)/test-suite/test_tools.cc $@

stub_debug.cc: $(top_srcdir)/src/tests/stub_debug.cc
	cp $(top_srcdir)/src/tests/stub_debug.cc $@

time.cc: $(top_srcdir)/src/time.cc
	cp $(top_srcdir)/src/time.cc $@

stub_libmem.cc: $(top_srcdir)/src/tests/stub_libmem.cc STUB.h
	cp $(top_srcdir)/src/tests/stub_libmem.cc $@
	
STUB.h: $(top_srcdir)/src/tests/STUB.h
	cp $(top_srcdir)/src/tests/STUB.h $@
	

# stock tools for unit tests - library independent versions of dlink_list
# etc.
# globals.cc is needed by test_tools.cc.
# Neither of these should be disted from here.
TESTSOURCES= test_tools.cc
CLEANFILES += test_tools.cc stub_debug.cc time.cc stub_libmem.cc STUB.h

## ##### squidclient  #####

bin_PROGRAMS = squidclient

squidclient_SOURCES = \
	gssapi_support.cc \
	gssapi_support.h \
	Parameters.h \
	Ping.cc \
	Ping.h \
	squidclient.cc \
	stub_debug.cc \
	test_tools.cc \
	stub_libmem.cc \
	STUB.h \
	time.cc \
	Transport.cc \
	Transport.h
