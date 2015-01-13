## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = log_file_daemon
log_file_daemon_SOURCES = log_file_daemon.cc
log_file_daemon_LDADD = \
	-L$(top_builddir)/lib $(COMPAT_LIB) \
	$(XTRA_LIBS)
EXTRA_DIST = required.m4
