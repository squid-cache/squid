#  Makefile for the eCAP library
#
#  $Id$
#

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

noinst_LTLIBRARIES = libeCAP.la

libeCAP_la_SOURCES = \
	Registry.h

INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
        -I$(top_srcdir)/src


# Sample adapter section.

EXTRA_DIST = \
	MinimalAdapter.cc
        
lib_LTLIBRARIES = MinimalAdapter.la
MinimalAdapter_la_SOURCES = MinimalAdapter.cc
MinimalAdapter_la_LDFLAGS = -module -avoid-version
MinimalAdapter_la_LIBADD = ./libeCAP.la
