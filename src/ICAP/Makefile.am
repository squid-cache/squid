#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2005/11/21 23:54:12 wessels Exp $
#
#  Uncomment and customize the following to suit your needs:
#

install: all
install-strip: all

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

SUBDIRS		= 

EXTRA_LIBRARIES	= \
	libicap.a

noinst_LIBRARIES = \
	libicap.a

libicap_a_SOURCES = \
 	ChunkedCodingParser.cc \
	ICAPClientRespmodPrecache.cc \
	ICAPClientReqmodPrecache.cc \
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
