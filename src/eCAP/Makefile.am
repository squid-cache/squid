#  Makefile for the eCAP library
#
#  $Id$
#

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

noinst_LTLIBRARIES = libeCAP.la

libeCAP_la_SOURCES = \
	Config.h \
	Config.cc \
	Host.h \
	Host.cc \
	MessageTranslator.h \
	MessageTranslator.cc \
	ServiceRep.h \
	ServiceRep.cc \
	XactionRep.h \
	XactionRep.cc \
	\
	Registry.h

INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
        -I$(top_srcdir)/src
