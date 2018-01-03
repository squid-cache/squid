## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

EXTRA_LTLIBRARIES = libaufs.la libdiskd.la libufs.la librock.la
noinst_LTLIBRARIES =  $(STORE_LIBS_TO_BUILD) libfs.la

# aufs is a "fake" legacy store
libaufs_la_SOURCES = \
	aufs/StoreFSaufs.cc

# diskd is a "fake" legacy store
libdiskd_la_SOURCES = \
	diskd/StoreFSdiskd.cc

libufs_la_SOURCES = \
	ufs/StoreFSufs.h \
	ufs/StoreFSufs.cc \
	ufs/UFSStoreState.cc \
	ufs/UFSSwapDir.cc \
	ufs/UFSSwapDir.h \
	ufs/UFSStrategy.cc \
	ufs/UFSStrategy.h \
	ufs/UFSStoreState.h \
	ufs/StoreSearchUFS.h \
	ufs/StoreSearchUFS.cc \
	ufs/UFSSwapLogParser.h \
	ufs/UFSSwapLogParser.cc \
	ufs/RebuildState.h \
	ufs/RebuildState.cc

librock_la_SOURCES = \
	rock/forward.h \
	rock/RockDbCell.cc \
	rock/RockDbCell.h \
	rock/RockHeaderUpdater.cc \
	rock/RockHeaderUpdater.h \
	rock/RockIoState.cc \
	rock/RockIoState.h \
	rock/RockIoRequests.cc \
	rock/RockIoRequests.h \
	rock/RockRebuild.cc \
	rock/RockRebuild.h \
	rock/RockStoreFileSystem.cc \
	rock/RockStoreFileSystem.h \
	rock/RockSwapDir.cc \
	rock/RockSwapDir.h

libfs_la_SOURCES = Module.cc Module.h
libfs_la_LIBADD =  $(STORE_LIBS_TO_BUILD)
libfs_la_DEPENDENCIES = $(STORE_LIBS_TO_BUILD)

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)


## targets below to emulate distributed makefiles
ufs/all: libufs.la
ufs/clean: clean
rock/all: librock.la
rock/clean: clean


TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/ufs/*.h $(srcdir)/rock/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1
## diskd/ has no .h files
## aufs/ has no .h files
## ./ has no .h files

CLEANFILES += testHeaders

.PHONY: testHeaders
