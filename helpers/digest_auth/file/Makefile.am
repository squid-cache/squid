include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

man_MANS = digest_file_auth.8
libexec_PROGRAMS = digest_file_auth
digest_file_auth_SOURCES = digest_file_auth.cc \
	digest_common.h \
	text_backend.cc \
	text_backend.h

LDADD = \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = digest_file_auth.8 required.m4
