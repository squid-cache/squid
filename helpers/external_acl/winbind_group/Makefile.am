#
#  Makefile for the wb_group external_acl helper
#
#  $Id: Makefile.am,v 1.4 2003/01/23 00:36:20 robertc Exp $
#

libexec_PROGRAMS = wb_group
wb_group_SOURCES = wb_check_group.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
EXTRA_DIST = readme.txt
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src
LDADD = -L$(top_builddir)/lib $(XTRA_LIBS)
