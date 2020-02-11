## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
	access_log.h \
	access_log.cc \
	Config.cc \
	Config.h \
	File.cc \
	File.h \
	FormatHttpdCombined.cc \
	FormatHttpdCommon.cc \
	Formats.h \
	FormatSquidCustom.cc \
	FormatSquidIcap.cc \
	FormatSquidNative.cc \
	FormatSquidReferer.cc \
	FormatSquidUseragent.cc \
	ModDaemon.cc \
	ModDaemon.h \
	ModStdio.cc \
	ModStdio.h \
	ModSyslog.cc \
	ModSyslog.h \
	ModUdp.cc \
	ModUdp.h \
	CustomLog.h \
	CustomLog.cc \
	TcpLogger.cc \
	TcpLogger.h

