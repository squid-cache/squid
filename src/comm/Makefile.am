include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libcomm.la

## Library holding comm socket handlers
libcomm_la_SOURCES= \
	AcceptLimiter.cc \
	AcceptLimiter.h \
	ListenStateData.cc \
	ListenStateData.h \
	\
	IoCallback.cc \
	IoCallback.h \
	Write.cc \
	Write.h \
	\
	comm_internal.h
