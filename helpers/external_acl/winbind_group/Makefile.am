#
#  Makefile for the wb_group external_acl helper
#
#  $Id: Makefile.am,v 1.3 2002/09/10 22:22:27 hno Exp $
#

libexec_PROGRAMS = wb_group
wb_group_SOURCES = wb_check_group.c wb_common.c samba_nss.h winbindd_nss.h wbntlm.h winbind_nss_config.h
EXTRA_DIST = readme.txt
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src
LDADD = -L$(top_builddir)/lib $(XTRA_LIBS)
