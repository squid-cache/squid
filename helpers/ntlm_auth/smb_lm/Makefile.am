include $(top_srcdir)/src/Common.am

SUBDIRS = smbval

libexec_PROGRAMS = ntlm_smb_lm_auth
ntlm_smb_lm_auth_SOURCES = libntlmssp.c ntlm_smb_lm_auth.c ntlm_smb_lm_auth.h

## we need our local files too (but avoid -I. at all costs)
INCLUDES += \
	-I$(srcdir) \
	-I$(srcdir)/smbval

ntlm_smb_lm_auth_LDADD = \
	-L$(top_builddir)/lib -lntlmauth \
	smbval/libsmbvalid.a \
	$(COMPAT_LIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

ntlm_smb_lm_auth_DEPENDENCIES = $(top_builddir)/lib/libntlmauth.a

EXTRA_DIST = config.test
