## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

if !ENABLE_WIN32SPECIFIC
bin_PROGRAMS = purge
man_MANS = purge.1
endif

purge_SOURCES = \
	convert.cc \
	convert.hh \
	socket.cc \
	socket.hh \
	signal.cc \
	signal.hh \
	squid-tlv.cc \
	squid-tlv.hh \
	copyout.cc \
	copyout.hh \
	conffile.cc \
	conffile.hh \
	purge.cc

purge_LDADD = \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

EXTRA_DIST = purge.1
