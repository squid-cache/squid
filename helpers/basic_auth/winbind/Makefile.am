#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.4 2002/05/23 14:01:19 hno Exp $
#

libexec_PROGRAMS = wb_auth
wb_auth_SOURCES = wb_basic_auth.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src
LDADD = -L$(top_builddir)/lib -lmiscutil -lntlmauth $(XTRA_LIBS)
