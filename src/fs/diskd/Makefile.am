#
#  Makefile for the DISKD storage driver for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2002/10/13 20:35:26 robertc Exp $
#

libexec_PROGRAMS = diskd
diskd_SOURCES = diskd.cc
LDADD = $(top_builddir)/lib/libmiscutil.a @XTRA_LIBS@

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/
