## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

noinst_LTLIBRARIES = libengines.la

libengines_la_SOURCES = \
	AsyncEngine.h \
	forward.h

# XXX: autoconf only supplies CXXCOMPILE et al. properly when there is a .cc to build.
# XXX: temporary workaround for make check testHeaders auto-build.
EXCLUDE_FROM_HDR_TESTING += $(libengines_la_SOURCES)
