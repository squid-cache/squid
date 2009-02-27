include $(top_srcdir)/src/Common.am

EXTRA_LIBRARIES = libaufs.a libdiskd.a libcoss.a libufs.a
noinst_LIBRARIES = @STORE_LIBS_TO_BUILD@

## TODO: add libfs -- file system framework; this library is always built
## TODO: use libtool and add @STORE_LIBS_TO_BUILD@ to libfs.la

# aufs is a "fake" legacy store
libaufs_a_SOURCES = \
	aufs/StoreFSaufs.cc

# diskd is a "fake" legacy store
libdiskd_a_SOURCES = \
	diskd/StoreFSdiskd.cc

libcoss_a_SOURCES = \
	coss/StoreFScoss.h \
	coss/StoreFScoss.cc \
	coss/store_coss.h \
	coss/store_io_coss.cc \
	coss/store_dir_coss.cc \
	coss/CossSwapDir.h

libufs_a_SOURCES = \
	ufs/StoreFSufs.h \
	ufs/StoreFSufs.cc \
	ufs/store_dir_ufs.cc \
	ufs/store_io_ufs.cc \
	ufs/ufscommon.cci \
	ufs/ufscommon.cc \
	ufs/ufscommon.h 


EXTRA_DIST = \
	coss/coss-notes.txt

# TODO: fix #include statements so that this is not needed
INCLUDES += -I.


check_PROGRAMS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/fs/ufs/*.h $(top_srcdir)/src/fs/coss/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/fs/ufs" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/fs/coss" || exit 1
## diskd/ has no .h files
## aufs/ has no .h files
## ./ has no .h files

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c

## targets below to emulate distributed makefiles
coss/all: libcoss.a
coss/clean: clean
ufs/all: libufs.a
ufs/clean: clean
