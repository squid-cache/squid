include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libanyp.la

libanyp_la_SOURCES = \
	PortCfg.cc \
	PortCfg.h \
	ProtocolType.cc \
	ProtocolType.h \
	ProtocolVersion.h

ProtocolType.cc: ProtocolType.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk <$(srcdir)/ProtocolType.h | sed -e 's%PROTO_%%' >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += ProtocolType.cc
