#
#  Makefile for the DISKD storage driver for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.3 2003/01/23 00:38:15 robertc Exp $
#

libexec_PROGRAMS = diskd
diskd_SOURCES = diskd.cc
LDADD = $(top_builddir)/lib/libmiscutil.a @XTRA_LIBS@

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/
