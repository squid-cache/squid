#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2008/05/17 10:23:13 serassio Exp $
#
#  Uncomment and customize the following to suit your needs:
#


libexec_PROGRAMS = mswin_check_ad_group

mswin_check_ad_group_SOURCES = mswin_check_ad_group.c mswin_check_ad_group.h

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src

LDADD   = -L$(top_builddir)/lib -lmiscutil -lnetapi32 -ladvapi32 \
          -lntdll $(XTRA_LIBS)

EXTRA_DIST = readme.txt
