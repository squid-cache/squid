#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.6 2003/01/23 00:35:52 robertc Exp $
#

libexec_PROGRAMS = wb_auth
wb_auth_SOURCES = wb_basic_auth.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
INCLUDES = -I$(top_srcdir)/include
LDADD = -L$(top_builddir)/lib -lmiscutil -lntlmauth $(XTRA_LIBS)
