## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
	ufs/RebuildState.cc \
	ufs/RebuildState.h \
	ufs/StoreFSufs.cc \
	ufs/StoreFSufs.h \
	ufs/UFSStoreState.cc \
	ufs/UFSStoreState.h \
	ufs/UFSStrategy.cc \
	ufs/UFSStrategy.h \
	ufs/UFSSwapDir.cc \
	ufs/UFSSwapDir.h \
	ufs/UFSSwapLogParser.cc \
	ufs/UFSSwapLogParser.h

librock_la_SOURCES = \
	rock/RockDbCell.cc \
	rock/RockDbCell.h \
	rock/RockHeaderUpdater.cc \
	rock/RockHeaderUpdater.h \
	rock/RockIoRequests.cc \
	rock/RockIoRequests.h \
	rock/RockIoState.cc \
	rock/RockIoState.h \
	rock/RockRebuild.cc \
	rock/RockRebuild.h \
	rock/RockStoreFileSystem.cc \
	rock/RockStoreFileSystem.h \
	rock/RockSwapDir.cc \
	rock/RockSwapDir.h \
	rock/forward.h

libfs_la_SOURCES = \
	Module.cc \
	Module.h
libfs_la_LIBADD =  $(STORE_LIBS_TO_BUILD)
libfs_la_DEPENDENCIES = $(STORE_LIBS_TO_BUILD)

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)


## targets below to emulate distributed makefiles
ufs/all: libufs.la
ufs/clean: clean
rock/all: librock.la
rock/clean: clean

