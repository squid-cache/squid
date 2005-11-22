#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2005/11/21 23:32:59 wessels Exp $
#
#  Uncomment and customize the following to suit your needs:
#

install: all
install-strip: all

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

SUBDIRS		= 

EXTRA_LIBRARIES	= \
	libicapclient.a

noinst_LIBRARIES = \
	libicapclient.a

libicapclient_a_SOURCES = \
 	ChunkedCodingParser.cc \
	ICAPAnchor.cc \
	ICAPClientSideHook.cc \
	ICAPClient.cc \
	ICAPElements.cc \
	ICAPXaction.cc \
	ICAPOptXact.cc \
	ICAPModXact.cc \
	ICAPServiceRep.cc \
	ICAPConfig.cc \
	ICAPOptions.cc \
	TextException.cc \
	MsgPipe.cc

INCLUDES        = -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src
