include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ntlm_smb_lm_auth
ntlm_smb_lm_auth_SOURCES = ntlm_smb_lm_auth.cc

ntlm_smb_lm_auth_LDADD = \
	$(top_builddir)/lib/smblib/libsmblib.la \
	$(top_builddir)/lib/rfcnb/librfcnb.la \
	$(top_builddir)/lib/ntlmauth/libntlmauth.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

INCLUDES += -I$(top_srcdir)/lib

EXTRA_DIST = config.test
