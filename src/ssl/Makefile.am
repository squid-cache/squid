include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsslsquid.la libsslutil.la

EXTRA_PROGRAMS = \
	ssl_crtd

EXTRA_DIST = \
	ssl_crtd.8

if USE_SSL_CRTD
SSL_CRTD = ssl_crtd
SSL_CRTD_SOURCE = \
    helper.cc \
    helper.h
else
SSL_CRTD =
SSL_CRTD_SOURCE =
endif

## SSL stuff used by main Squid but not by ssl_crtd
libsslsquid_la_SOURCES = \
	context_storage.cc \
	context_storage.h \
	Config.cc \
	Config.h \
	ErrorDetail.cc \
	ErrorDetail.h \
	ErrorDetailManager.cc \
	ErrorDetailManager.h \
	ProxyCerts.h \
	ServerBump.cc \
	ServerBump.h \
	support.cc \
	support.h \
	\
	$(SSL_CRTD_SOURCE)

## SSL stuff used by main Squid and ssl_crtd
libsslutil_la_SOURCES = \
	gadgets.cc \
	gadgets.h \
	crtd_message.cc \
	crtd_message.h

libexec_PROGRAMS = \
	$(SSL_CRTD)

if USE_SSL_CRTD
ssl_crtd_SOURCES = ssl_crtd.cc certificate_db.cc certificate_db.h
ssl_crtd_LDADD = libsslutil.la $(SSLLIB) $(COMPAT_LIB)
endif
