## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am
include $(top_srcdir)/doc/manuals/Substitute.am

security_file_certgen.8: $(srcdir)/security_file_certgen.8.in Makefile
	$(SUBSTITUTE) < $(srcdir)/security_file_certgen.8.in > $@

man_MANS = security_file_certgen.8
CLEANFILES += security_file_certgen.8
EXTRA_DIST = security_file_certgen.8.in

libexec_PROGRAMS = security_file_certgen

security_file_certgen_SOURCES = \
	certificate_db.cc \
	certificate_db.h \
	security_file_certgen.cc

security_file_certgen_LDADD = \
	$(top_builddir)/src/ssl/libsslutil.la \
	$(top_builddir)/src/sbuf/libsbuf.la \
	$(top_builddir)/src/debug/libdebug.la \
	$(top_builddir)/src/error/liberror.la \
	$(top_builddir)/src/comm/libminimal.la \
	$(top_builddir)/src/mem/libminimal.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/src/time/libtime.la \
	$(SSLLIB) \
	$(COMPAT_LIB)

