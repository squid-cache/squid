#
#  Makefile for the wb_group external_acl helper
#
#  $Id: Makefile.am,v 1.5 2003/02/11 14:34:41 hno Exp $
#

libexec_PROGRAMS = wb_group
wb_group_SOURCES = wb_check_group.c wb_common.c wbntlm.h
EXTRA_DIST = readme.txt
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src -I@SAMBASOURCES@
LDADD = -L$(top_builddir)/lib $(XTRA_LIBS)
