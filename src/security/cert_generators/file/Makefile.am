## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

man_MANS = security_file_certgen.8
libexec_PROGRAMS = security_file_certgen

security_file_certgen_SOURCES = \
	certificate_db.cc \
	certificate_db.h \
	security_file_certgen.cc
security_file_certgen_LDADD = \
	$(top_builddir)/src/ssl/libsslutil.la \
	$(SSLLIB) \
	$(COMPAT_LIB)

EXTRA_DIST = security_file_certgen.8

