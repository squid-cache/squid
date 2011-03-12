include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsquid-ecap.la

libsquid_ecap_la_SOURCES = \
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
libsquid_ecap_la_CXXFLAGS = $(EXT_LIBECAP_CFLAGS)
libsquid_ecap_la_LIBADD = $(EXT_LIBECAP_LIBS) 
