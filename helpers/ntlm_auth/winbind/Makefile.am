#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.4 2002/05/20 02:03:57 hno Exp $
#

libexec_PROGRAMS = wb_ntlmauth
wb_ntlmauth_SOURCES = wb_ntlm_auth.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
EXTRA_DIST = \
	patches/wb_common.patch \
	patches/winbind_nss_config.patch
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src
LDADD = -L$(top_builddir)/lib -lmiscutil -lntlmauth -lm
