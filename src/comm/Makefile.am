include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libcomm.la

## First group are listener comm socket handlers
## Second group are outbound connection setup handlers
## Third group are misc shared comm objects
libcomm_la_SOURCES= \
	AcceptLimiter.cc \
	AcceptLimiter.h \
	ListenStateData.cc \
	ListenStateData.h \
	\
	ConnectStateData.cc \
	ConnectStateData.h \
	\
	Connection.cc \
	Connection.h \
	comm_err_t.h \
	comm_internal.h \
	forward.h
