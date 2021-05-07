## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

DIST_SUBDIRS= DB file
SUBDIRS= $(LOG_DAEMON_HELPERS)
EXTRA_DIST= helpers.m4

noinst_LTLIBRARIES = liblog.la

liblog_la_SOURCES = \
	Config.cc \
	Config.h \
	CustomLog.cc \
	CustomLog.h \
	File.cc \
	File.h \
	FormatHttpdCombined.cc \
	FormatHttpdCommon.cc \
	FormatSquidCustom.cc \
	FormatSquidIcap.cc \
	FormatSquidNative.cc \
	FormatSquidReferer.cc \
	FormatSquidUseragent.cc \
	Formats.h \
	ModDaemon.cc \
	ModDaemon.h \
	ModStdio.cc \
	ModStdio.h \
	ModSyslog.cc \
	ModSyslog.h \
	ModUdp.cc \
	ModUdp.h \
	TcpLogger.cc \
	TcpLogger.h \
	access_log.cc \
	access_log.h \
	forward.h

