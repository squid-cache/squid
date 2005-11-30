#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.3 2005/11/29 18:08:10 serassio Exp $
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
 	ChunkedCodingParser.h \
	ICAPClient.cc \
	ICAPClient.h \
	ICAPClientReqmodPrecache.cc \
	ICAPClientReqmodPrecache.h \
	ICAPClientRespmodPrecache.cc \
	ICAPClientRespmodPrecache.h \
	ICAPConfig.cc \
	ICAPConfig.h \
	ICAPElements.cc \
	ICAPElements.h \
	ICAPModXact.cc \
	ICAPModXact.h \
	ICAPOptions.cc \
	ICAPOptions.h \
	ICAPOptXact.cc \
	ICAPOptXact.h \
	ICAPServiceRep.cc \
	ICAPServiceRep.h \
	ICAPXaction.cc \
	ICAPXaction.h \
	MsgPipe.cc \
	MsgPipe.h \
	MsgPipeData.h \
	MsgPipeEnd.h \
	MsgPipeSink.h \
	MsgPipeSource.h \
	TextException.cc \
	TextException.h

INCLUDES        = -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/src
