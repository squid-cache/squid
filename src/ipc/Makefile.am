include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libipc.la

libipc_la_SOURCES = \
	AtomicWord.h \
	FdNotes.cc \
	FdNotes.h \
	Kid.cc \
	Kid.h \
	Kids.cc \
	Kids.h \
	Messages.h \
	Queue.cc \
	Queue.h \
	StartListening.cc \
	StartListening.h \
	StrandCoord.cc \
	StrandCoord.h \
	StrandCoords.h \
	StrandSearch.cc \
	StrandSearch.h \
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
	\
	forward.h \
	\
	mem/Page.cc \
	mem/Page.h \
	mem/PagePool.cc \
	mem/PagePool.h \
	mem/Pages.cc \
	mem/Pages.h \
	mem/PageStack.cc \
	mem/PageStack.h \
	mem/Segment.cc \
	mem/Segment.h

DEFS += -DDEFAULT_PREFIX=\"$(prefix)\"
