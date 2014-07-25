include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

AM_CPPFLAGS += -I$(top_srcdir)/lib

noinst_LTLIBRARIES = libntlmauth.la

libntlmauth_la_SOURCES = \
	ntlmauth.cc \
	ntlmauth.h \
	support_bits.cci
