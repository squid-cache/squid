include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ntlm_fake_auth
ntlm_fake_auth_SOURCES	= ntlm_fake_auth.cc

ntlm_fake_auth_LDADD = \
	-L$(top_builddir)/libntlmauth -lntlmauth \
	$(COMPAT_LIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

## Demo using perl.
## ntlm_fake_auth.pl: ntlm_fake_auth.pl.in
##	$(subst_perlshell)

EXTRA_DIST = config.test \
	ntlm_fake_auth.pl.in
