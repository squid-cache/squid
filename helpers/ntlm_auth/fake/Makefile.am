include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ntlm_fake_auth
ntlm_fake_auth_SOURCES	= ntlm_fake_auth.cc

ntlm_fake_auth_LDADD = \
	-L$(top_builddir)/lib -lntlmauth \
	$(COMPAT_LIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

ntlm_fake_auth_DEPENDENCIES = $(top_builddir)/lib/libntlmauth.a

EXTRA_DIST = config.test
