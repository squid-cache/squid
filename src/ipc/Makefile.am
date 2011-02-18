include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libipc.la

libipc_la_SOURCES = \
	FdNotes.cc \
	FdNotes.h \
	Kid.cc \
	Kid.h \
	Kids.cc \
	Kids.h \
	Messages.h \
	StartListening.cc \
	StartListening.h \
	StrandCoord.cc \
	StrandCoord.h \
	StrandCoords.h \
	SharedListen.cc \
	SharedListen.h \
	TypedMsgHdr.cc \
	TypedMsgHdr.h \
	Coordinator.cc \
	Coordinator.h \
	UdsOp.cc \
	UdsOp.h \
	Port.cc \
	Port.h \
	Strand.cc \
	Strand.h \
	forward.h \
	Forwarder.cc \
	Forwarder.h \
	Inquirer.cc \
	Inquirer.h \
	Request.h \
	Response.h

DEFS += -DDEFAULT_PREFIX=\"$(prefix)\"
