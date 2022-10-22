## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = \
	libmem.la \
	libminimal.la

noinst_HEADERS = \
	AllocatorProxy.h \
	Sensitive.h \
	forward.h

# a full-featured memory management library for sbin/squid use
libmem_la_SOURCES = \
	AllocatorBase.cc \
	AllocatorBase.h \
	AllocatorMetrics.cc \
	AllocatorMetrics.h \
	AllocatorProxy.cc \
	Meter.h \
	Pool.cc \
	Pool.h \
	PoolChunked.cc \
	PoolChunked.h \
	PoolMalloc.cc \
	PoolMalloc.h \
	PoolsManager.cc \
	PoolsManager.h \
	PoolingAllocator.h \
	Stats.h \
	old_api.cc

# a bare-bones implementation of few libmem.la APIs sufficient for helpers use
libminimal_la_SOURCES = \
	minimal.cc
