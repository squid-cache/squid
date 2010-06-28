include $(top_srcdir)/src/Common.am

man_MANS = ntlm_sspi_auth.8

libexec_PROGRAMS = ntlm_sspi_auth

ntlm_sspi_auth_SOURCES = ntlm_sspi_auth.cc

LDADD = \
	-L$(top_builddir)/libntlmauth -lntlmauth \
	-L$(top_builddir)/lib -lsspwin32 \
	$(COMPAT_LIB) \
	-lnetapi32 \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST = ntlm_sspi_auth.8 config.test
