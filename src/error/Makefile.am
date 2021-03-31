## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

categories.cc: forward.h $(top_srcdir)/src/mk-string-arrays.awk
	$(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk ifile=error/forward.h < $(srcdir)/forward.h > $@ || ($(RM) -f $@ && exit 1)

BUILT_SOURCES = \
	categories.cc

noinst_LTLIBRARIES = liberror.la

liberror_la_SOURCES = \
	Detail.cc \
	Detail.h \
	Error.cc \
	Error.h \
	ExceptionErrorDetail.h \
	SysErrorDetail.h \
	forward.h

nodist_liberror_la_SOURCES = \
	$(BUILT_SOURCES)

CLEANFILES += \
	$(BUILT_SOURCES)

