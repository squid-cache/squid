#
#  Makefile for the wb_group external_acl helper
#
#  $Id: Makefile.am,v 1.1 2002/07/07 18:18:12 hno Exp $
#

libexec_PROGRAMS = wb_group
wb_auth_SOURCES = wb_check_group.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src
LDADD = -L$(top_builddir)/lib -lmiscutil -lntlmauth $(XTRA_LIBS)
