include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsquid-http.la

libsquid_http_la_SOURCES = \
	MethodType.cc \
	MethodType.h \
	ProtocolVersion.h \
	StatusCode.cc \
	StatusCode.h \
	StatusLine.cc \
	StatusLine.h

MethodType.cc: MethodType.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk < $(srcdir)/MethodType.h | \
		sed -e 's%METHOD_%%' -e 's%_C%-C%' >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += MethodType.cc
