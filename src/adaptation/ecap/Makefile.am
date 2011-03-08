include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libxecap.la

libxecap_la_SOURCES = \
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
libxecap_la_CXXFLAGS = $(EXTLIBECAP_CFLAGS)

## It is tempting to put libxecap_la_LDFLAGS/LIBADD here, but it leads to weird
## linking errors. For example, "make clean all" works, but rebuilding after
## modifying a single source file leads to libtool's "file not found" errors.
## libxecap_la_LIBADD = $(EXTLIBECAP_LIBS)
