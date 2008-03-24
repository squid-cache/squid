AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
        -I$(top_srcdir)/src

noinst_LTLIBRARIES = libadaptation.la

libadaptation_la_SOURCES = \
	Elements.cc \
	Elements.h \
	Service.cc \
	Service.h \
	Xaction.cc \
	Xaction.h

check_PROGRAMS = testHeaders

## test .h correctness
testHeaders: *.h
	$(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "." || exit 1
