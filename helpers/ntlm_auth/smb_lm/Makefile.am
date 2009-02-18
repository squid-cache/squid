#
#  Makefile for the Squid Object Cache server
#

SUBDIRS = smbval

libexec_PROGRAMS = ntlm_smb_lm_auth
ntlm_smb_lm_auth_SOURCES = libntlmssp.c ntlm_smb_lm_auth.c ntlm_smb_lm_auth.h

INCLUDES = \
	-I$(top_srcdir) \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	-I$(srcdir)/smbval

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lntlmauth -lmiscutil \
	smbval/libsmbvalid.a \
	$(CRYPTLIB) \
	$(XTRA_LIBS)
