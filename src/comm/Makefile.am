## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libcomm.la

## Library holding comm socket handlers
libcomm_la_SOURCES= \
	AcceptLimiter.cc \
	AcceptLimiter.h \
	ConnOpener.cc \
	ConnOpener.h \
	Connection.cc \
	Connection.h \
	Flag.h \
	forward.h \
	IoCallback.cc \
	IoCallback.h \
	Loops.h \
	ModDevPoll.cc \
	ModEpoll.cc \
	ModKqueue.cc \
	ModPoll.cc \
	ModSelect.cc \
	ModSelectWin32.cc \
	Read.cc \
	Read.h \
	TcpAcceptor.cc \
	TcpAcceptor.h \
	UdpOpenDialer.h \
	Write.cc \
	Write.h \
	\
	comm_internal.h
