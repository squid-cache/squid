AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
CLEANFILES =

INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
        -I$(top_srcdir)/src

noinst_LTLIBRARIES = libadaptation.la

libadaptation_la_SOURCES = \
	AccessCheck.cc \
	AccessCheck.h \
	AccessRule.cc \
	AccessRule.h \
	Config.cc \
	Config.h \
	Elements.cc \
	Elements.h \
	forward.h \
	Initiate.cc \
	Initiate.h \
	Initiator.cc \
	Initiator.h \
	Message.cc \
	Message.h \
	Service.cc \
	Service.h \
	ServiceConfig.cc \
	ServiceConfig.h \
	ServiceGroups.cc \
	ServiceGroups.h

check_PROGRAMS = testHeaders

## test .h correctness
testHeaders: $(top_srcdir)/src/adaptation/*.h
	$(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "." || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
