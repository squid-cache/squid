## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

DIST_SUBDIRS= ecap icap
SUBDIRS =

noinst_LTLIBRARIES = libadaptation.la

libadaptation_la_SOURCES = \
	AccessCheck.cc \
	AccessCheck.h \
	AccessRule.cc \
	AccessRule.h \
	Answer.cc \
	Answer.h \
	Config.cc \
	Config.h \
	DynamicGroupCfg.cc \
	DynamicGroupCfg.h \
	Elements.cc \
	Elements.h \
	forward.h \
	Initiate.cc \
	Initiate.h \
	Initiator.cc \
	Initiator.h \
	Iterator.cc \
	Iterator.h \
	Message.cc \
	Message.h \
	Service.cc \
	Service.h \
	ServiceConfig.cc \
	ServiceConfig.h \
	ServiceGroups.cc \
	ServiceGroups.h \
	ServiceFilter.cc \
	ServiceFilter.h \
	History.cc \
	History.h

libadaptation_la_LIBADD =

if ENABLE_ECAP
SUBDIRS += ecap
libadaptation_la_LIBADD += ecap/libecapsquid.la
endif

if ENABLE_ICAP_CLIENT
SUBDIRS += icap
libadaptation_la_LIBADD += icap/libicap.la
endif

