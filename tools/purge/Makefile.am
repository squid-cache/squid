include $(top_srcdir)/src/Common.am

bin_PROGRAMS = purge

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

EXTRA_DIST = README
