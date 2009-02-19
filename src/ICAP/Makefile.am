AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
CLEANFILES =

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
        -I$(top_srcdir)/src

noinst_LTLIBRARIES = libicap.la

libicap_la_SOURCES = \
	ICAPClient.cc \
	ICAPClient.h \
	ICAPInOut.h \
	ICAPConfig.cc \
	ICAPConfig.h \
	ICAPElements.cc \
	ICAPElements.h \
	ICAPOptions.cc \
	ICAPOptions.h \
	ICAPServiceRep.cc \
	ICAPServiceRep.h \
	ICAPLauncher.cc \
	ICAPLauncher.h \
	ICAPOptXact.cc \
	ICAPOptXact.h \
	ICAPXaction.cc \
	ICAPXaction.h \
	ICAPModXact.cc \
	ICAPModXact.h


check_PROGRAMS = testHeaders

## test .h correctness
testHeaders: $(top_srcdir)/src/ICAP/*.h
	$(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "." || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
