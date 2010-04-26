include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libipc.la

libipc_la_SOURCES = \
	Kid.cc \
	Kid.h \
	Kids.cc \
	Kids.h \
	Coordinator.cc \
	Coordinator.h \
	UdsOp.cc \
	UdsOp.h \
	Port.cc \
	Port.h \
	Strand.cc \
	Strand.h

DEFS += -DDEFAULT_PREFIX=\"$(prefix)\"
