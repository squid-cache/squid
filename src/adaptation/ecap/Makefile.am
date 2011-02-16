include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libecap.la

libecap_la_SOURCES = \
	Config.h \
	Config.cc \
	Host.h \
	Host.cc \
	MessageRep.h \
	MessageRep.cc \
	ServiceRep.h \
	ServiceRep.cc \
	XactionRep.h \
	XactionRep.cc \
	\
	Registry.h

# add libecap using its pkg-config-produced configuration variables
libecap_la_LDFLAGS = $(EXTLIBECAP_LIBS)
libecap_la_CPPFLAGS = $(EXTLIBECAP_CFLAGS)
