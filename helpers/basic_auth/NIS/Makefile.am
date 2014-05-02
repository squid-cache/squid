include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

libexec_PROGRAMS = basic_nis_auth

basic_nis_auth_SOURCES = \
	basic_nis_auth.cc \
	nis_support.h \
	nis_support.cc

basic_nis_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = required.m4
