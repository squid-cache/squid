include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ntlm_smb_lm_auth
ntlm_smb_lm_auth_SOURCES = ntlm_smb_lm_auth.cc

ntlm_smb_lm_auth_LDADD = \
	-L$(top_builddir)/libntlmauth -lntlmauth \
	$(COMPAT_LIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = config.test
