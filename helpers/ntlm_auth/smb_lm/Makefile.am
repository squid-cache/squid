#
#  Makefile for the Squid Object Cache server
#

include $(top_srcdir)/src/Common.am

SUBDIRS = smbval

libexec_PROGRAMS = ntlm_smb_lm_auth
ntlm_smb_lm_auth_SOURCES = libntlmssp.c ntlm_smb_lm_auth.c ntlm_smb_lm_auth.h

## we need our local files too (but avoid -I. at all costs)
INCLUDES += \
	-I$(srcdir) \
	-I$(srcdir)/smbval

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lntlmauth -lmiscutil \
	smbval/libsmbvalid.a \
	$(CRYPTLIB) \
	$(XTRA_LIBS)
