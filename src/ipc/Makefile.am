## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

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
	MemMap.cc \
	MemMap.h \
	Queue.cc \
	Queue.h \
	ReadWriteLock.cc \
	ReadWriteLock.h \
	StartListening.cc \
	StartListening.h \
	StoreMap.cc \
	StoreMap.h \
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
	forward.h \
	Forwarder.cc \
	Forwarder.h \
	Inquirer.cc \
	Inquirer.h \
	Request.h \
	Response.h \
	\
	mem/FlexibleArray.h \
	mem/Page.cc \
	mem/Page.h \
	mem/PagePool.cc \
	mem/PagePool.h \
	mem/Pages.cc \
	mem/Pages.h \
	mem/PageStack.cc \
	mem/PageStack.h \
	mem/Pointer.h \
	mem/Segment.cc \
	mem/Segment.h

DEFS += -DDEFAULT_STATEDIR=\"$(localstatedir)/run/squid\"

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/run/squid;
