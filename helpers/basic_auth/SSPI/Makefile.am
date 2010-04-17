include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

libexec_PROGRAMS = basic_sspi_auth

basic_sspi_auth_SOURCES = basic_sspi_auth.cc valid.cc valid.h
basic_sspi_auth_LDADD = \
	$(COMPAT_LIB) \
	-lnetapi32 -ladvapi32 -lsspwin32 \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt config.test
