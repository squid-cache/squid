#
#  Makefile for the wb_group external_acl helper
#
#  $Id: Makefile.am,v 1.7 2004/08/14 22:54:53 hno Exp $
#

libexec_PROGRAMS = wb_group
wb_group_SOURCES = wb_check_group.c wb_common.c wbntlm.h wb_common.h
EXTRA_DIST = readme.txt

LDADD		= -L$(top_builddir)/lib -lmiscutil @XTRA_LIBS@
INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include -I@SAMBASOURCES@
