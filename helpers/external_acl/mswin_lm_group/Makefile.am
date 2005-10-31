#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2005/10/31 16:29:45 serassio Exp $
#
#  Uncomment and customize the following to suit your needs:
#


libexec_PROGRAMS = mswin_check_lm_group

mswin_check_lm_group_SOURCES = win32_check_group.c win32_check_group.h

INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src

LDADD   = -L$(top_builddir)/lib -lmiscutil -lnetapi32 -ladvapi32 \
          -lntdll $(XTRA_LIBS)

EXTRA_DIST = readme.txt
