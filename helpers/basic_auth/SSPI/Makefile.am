include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

libexec_PROGRAMS = basic_sspi_auth

basic_sspi_auth_SOURCES = basic_sspi_auth.cc valid.cc valid.h
basic_sspi_auth_LDADD = \
	-L$(top_builddir)/lib -lsspwin32 \
	$(COMPAT_LIB) \
	-lnetapi32 -ladvapi32
	$(XTRA_LIBS)

man_MANS = basic_db_auth.8
EXTRA_DIST = basic_sspi_auth.8 config.test
