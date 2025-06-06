## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

EXTRA_DIST = \
	$(srcdir)/squidconf/* \
	test-functionality.sh \
	test-sources.sh \
	test-squid-conf.sh \
	testHeader.cc.in

## Sort by dependencies - test lowest layers first
TESTS += \
	syntheticoperators \
	VirtualDeleteOperator \
	splay\
	mem_node_test\
	mem_hdr_test

## Sort by alpha - any build failures are significant.
check_PROGRAMS += \
		mem_node_test\
		mem_hdr_test \
		splay \
		syntheticoperators \
		VirtualDeleteOperator

#do not include stub_libmem.cc here, as it would override libmem.la in
# several tests whose purpose is testing libmem itself.
STUBS = \
	stub_cbdata.cc \
	stub_MemBuf.cc \
	stub_SBuf.cc \
	stub_tools.cc \
	stub_fatal.cc \
	stub_libtime.cc \
	STUB.h
DEBUG_SOURCE = test_tools.cc $(STUBS)
CLEANFILES += $(STUBS) stub_libmem.cc

stub_cbdata.cc: $(top_srcdir)/src/tests/stub_cbdata.cc
	cp $(top_srcdir)/src/tests/stub_cbdata.cc $@

stub_MemBuf.cc: $(top_srcdir)/src/tests/stub_MemBuf.cc
	cp $(top_srcdir)/src/tests/stub_MemBuf.cc $@

stub_SBuf.cc: $(top_srcdir)/src/tests/stub_SBuf.cc
	cp $(top_srcdir)/src/tests/stub_SBuf.cc $@

stub_tools.cc: $(top_srcdir)/src/tests/stub_tools.cc
	cp $(top_srcdir)/src/tests/stub_tools.cc $@

stub_fatal.cc: $(top_srcdir)/src/tests/stub_fatal.cc
	cp $(top_srcdir)/src/tests/stub_fatal.cc $@

stub_libmem.cc: $(top_srcdir)/src/tests/stub_libmem.cc STUB.h
	cp $(top_srcdir)/src/tests/stub_libmem.cc $@

stub_libtime.cc: $(top_srcdir)/src/tests/stub_libtime.cc STUB.h
	cp $(top_srcdir)/src/tests/stub_libtime.cc $@

STUB.h: $(top_srcdir)/src/tests/STUB.h
	cp $(top_srcdir)/src/tests/STUB.h $@

mem_node_test_SOURCES = \
	$(DEBUG_SOURCE) \
	mem_node_test.cc
mem_node_test_LDADD = \
	$(top_builddir)/src/mem_node.o \
	$(top_builddir)/src/mem/libmem.la \
	$(top_builddir)/src/debug/libdebug.la \
	$(top_builddir)/src/comm/libminimal.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

mem_hdr_test_SOURCES = \
	$(DEBUG_SOURCE) \
	mem_hdr_test.cc
mem_hdr_test_LDADD = \
	$(top_builddir)/src/stmem.o \
	$(top_builddir)/src/mem_node.o \
	$(top_builddir)/src/mem/libmem.la \
	$(top_builddir)/src/debug/libdebug.la \
	$(top_builddir)/src/comm/libminimal.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

splay_SOURCES = \
	$(DEBUG_SOURCE) \
	splay.cc \
	stub_libmem.cc
splay_LDADD = \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

syntheticoperators_SOURCES = \
	$(DEBUG_SOURCE) \
	stub_libmem.cc \
	syntheticoperators.cc
syntheticoperators_LDADD = \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

VirtualDeleteOperator_SOURCES = \
	$(DEBUG_SOURCE) \
	VirtualDeleteOperator.cc \
	stub_libmem.cc
VirtualDeleteOperator_LDADD = \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

installcheck-local: squid-conf-tests

squid-conf-tests: $(srcdir)/test-squid-conf.sh $(top_builddir)/src/squid.conf.default $(srcdir)/squidconf/*
	@instructionFiles="$(srcdir)/squidconf/*.conf.instructions"; \
	for instructionFile in $$instructionFiles; do \
		cfgBasename=`basename $$instructionFile .instructions`; \
		cfg=$(srcdir)/squidconf/$$cfgBasename; \
		if ! test -f $$cfg; then \
			echo "FAIL: $$instructionFile has no matching $$cfg"; \
			exit 1; \
		fi; \
	done; \
	failed=0; \
	cfglist="$(top_builddir)/src/squid.conf.default $(srcdir)/squidconf/*.conf"; \
	rm -f $@ || $(TRUE); \
	for cfg in $$cfglist ; do \
		$(srcdir)/test-squid-conf.sh $(top_builddir) $(sbindir) $$cfg || \
			{ echo "FAIL: squid.conf test: $$cfg" | \
				sed s%$(top_builddir)/src/%% | \
				sed s%$(srcdir)/squidconf/%% ; \
				failed=1; break; \
			}; \
		if test "$$failed" -eq 0; then \
			echo "PASS: squid.conf test: $$cfg" | \
				sed s%$(top_builddir)/src/%% | \
				sed s%$(srcdir)/squidconf/%% ; \
		else break; fi; \
	done; \
	if test "$$failed" -eq 0; then cp $(TRUE) $@ ; else exit 1; fi

CLEANFILES += \
	squid-conf-tests \
	squid-expected-messages \
	squid-stderr.log \
	squid-stderr.log.next \
	squid-stderr.log.unmatched
