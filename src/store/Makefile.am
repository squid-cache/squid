## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

SUBDIRS= id_rewriters

noinst_LTLIBRARIES = libstore.la

libstore_la_SOURCES= \
	Controlled.h \
	Controller.cc \
	Controller.h \
	Disk.cc \
	Disk.h \
	Disks.cc \
	Disks.h \
	forward.h \
	LocalSearch.cc \
	LocalSearch.h \
	Storage.h
