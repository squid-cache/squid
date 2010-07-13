include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = negotiate_sspi_auth

negotiate_sspi_auth_SOURCES = negotiate_sspi_auth.cc

LDADD	= \
	-L$(top_builddir)/lib -lsspwin32 \
	$(COMPAT_LIB) \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt config.test
