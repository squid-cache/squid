AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
        -I$(top_srcdir)/src

noinst_LTLIBRARIES = libadaptation.la

libadaptation_la_SOURCES = \
	Config.cc \
	Config.h \
	Elements.cc \
	Elements.h \
	forward.h \
	Initiate.cc \
	Initiate.h \
	Initiator.cc \
	Initiator.h \
	Service.cc \
	Service.h \
	ServiceConfig.cc \
	ServiceConfig.h \
	Xaction.cc \
	Xaction.h

check_PROGRAMS = testHeaders

## test .h correctness
testHeaders: *.h
	$(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "." || exit 1
