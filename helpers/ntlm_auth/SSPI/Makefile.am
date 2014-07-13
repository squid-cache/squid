include $(top_srcdir)/src/Common.am

man_MANS = ntlm_sspi_auth.8

libexec_PROGRAMS = ntlm_sspi_auth

ntlm_sspi_auth_SOURCES = ntlm_sspi_auth.cc

LDADD = \
	$(top_builddir)/lib/ntlmauth/libntlmauth.la \
	-L$(top_builddir)/lib -lsspwin32 \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-lnetapi32 \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST = ntlm_sspi_auth.8 required.m4
