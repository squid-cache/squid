#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.5 2002/08/12 01:11:57 hno Exp $
#

libexec_PROGRAMS = wb_auth
wb_auth_SOURCES = wb_basic_auth.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
INCLUDES = -I$(top_srcdir)/include
LDADD = -L$(top_builddir)/lib -lmiscutil -lntlmauth $(XTRA_LIBS)
