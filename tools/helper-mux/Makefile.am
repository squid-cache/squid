## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.

include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= helper-mux
CLEANFILES += helper-mux
EXTRA_DIST= helper-mux.pl.in

helper-mux: helper-mux.pl.in
	$(subst_perlshell)

if ENABLE_DOCUMENTATION
man_MANS = helper-mux.8
CLEANFILES += helper-mux.8
EXTRA_DIST += helper-mux.8
endif
