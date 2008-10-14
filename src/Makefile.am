#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.201 2008/02/26 00:19:29 rousskov Exp $
#
#  Uncomment and customize the following to suit your needs:
#


AUTOMAKE_OPTIONS = subdir-objects
if USE_DNSSERVER
DNSSOURCE = dns.cc
DNSSERVER = dnsserver
else
DNSSOURCE = dns_internal.cc
DNSSERVER =
endif

SNMP_ALL_SOURCE = \
	snmp_core.cc \
	snmp_agent.cc
if USE_SNMP
SNMP_SOURCE = $(SNMP_ALL_SOURCE)
else
SNMP_SOURCE = 
endif

LOADABLE_MODULES_SOURCES = \
	LoadableModule.h \
	LoadableModule.cc \
	LoadableModules.h \
	LoadableModules.cc

TESTS=$(check_PROGRAMS)
check_PROGRAMS=

SUBDIRS		= fs repl auth

if USE_ADAPTATION
SUBDIRS += adaptation
endif

if USE_ICAP_CLIENT
SUBDIRS += ICAP
endif

if USE_ECAP
SUBDIRS += eCAP
endif

ADAPTATION_LIBS = @ECAP_LIBS@ @ICAP_LIBS@ @ADAPTATION_LIBS@

DELAY_POOL_ALL_SOURCE = \
	CommonPool.h \
	CompositePoolNode.h \
	delay_pools.cc \
	DelayId.cc \
	DelayId.h \
	DelayIdComposite.h \
	DelayBucket.cc \
	DelayBucket.h \
	DelayConfig.cc \
	DelayConfig.h \
	DelayPool.cc \
	DelayPool.h \
	DelayPools.h \
	DelaySpec.cc \
	DelaySpec.h \
	DelayTagged.cc \
	DelayTagged.h \
	DelayUser.cc \
	DelayUser.h \
	DelayVector.cc \
	DelayVector.h \
	NullDelayId.cc \
	NullDelayId.h
if USE_DELAY_POOLS
DELAY_POOL_SOURCE = $(DELAY_POOL_ALL_SOURCE)
else
DELAY_POOL_SOURCE = 
endif

ESI_ALL_SOURCE = \
	ElementList.h \
	ESI.cc \
	ESI.h \
	ESIAssign.cc \
	ESIAssign.h \
	ESIAttempt.h \
	ESIContext.cc \
	ESIContext.h \
	ESICustomParser.cc \
	ESICustomParser.h \
	ESIElement.h \
	ESIExcept.h \
	ESIExpatParser.cc \
	ESIExpatParser.h \
	ESIExpression.cc \
	ESIExpression.h \
	ESIInclude.cc \
	ESIInclude.h \
	ESILiteral.h \
	ESILibxml2Parser.cc \
	ESILibxml2Parser.h \
	ESIParser.cc \
	ESIParser.h \
	ESISegment.cc \
	ESISegment.h \
	ESISequence.cc \
	ESISequence.h \
	ESIVar.h \
	ESIVarState.cc \
	ESIVarState.h
if USE_ESI
  ESI_SOURCE = $(ESI_ALL_SOURCE)
else
  ESI_SOURCE = 
endif

if ENABLE_XPROF_STATS
XPROF_STATS_SOURCE = ProfStats.cc
else
XPROF_STATS_SOURCE = 
endif

if ENABLE_HTCP
HTCPSOURCE = htcp.cc htcp.h
endif

if MAKE_LEAKFINDER
LEAKFINDERSOURCE =  LeakFinder.cc
else
LEAKFINDERSOURCE = 
endif

if ENABLE_UNLINKD
UNLINKDSOURCE = unlinkd.cc
UNLINKD = unlinkd
else
UNLINKDSOURCE = 
UNLINKD = 
endif

if ENABLE_PINGER
PINGER = pinger
else
PINGER = 
endif

# Squid Internal ICMP sources
ICMPSOURCE = \
	ICMP.h \
	icmp.cc \
	ICMPConfig.h \
	ICMPSquid.h \
	ICMPSquid.cc

SSL_ALL_SOURCE = \
	ACLCertificateData.cc \
	ACLCertificateData.h  \
	ACLCertificate.cc \
	ACLCertificate.h  \
	ACLSslError.cc \
	ACLSslError.h \
	ACLSslErrorData.cc \
	ACLSslErrorData.h \
	ssl_support.cc \
	ssl_support.h

if ENABLE_SSL
SSL_SOURCE = $(SSL_ALL_SOURCE)
else
SSL_SOURCE = 
endif

WIN32_ALL_SOURCE = \
	win32.cc \
	WinSvc.cc
if ENABLE_WIN32SPECIFIC
WIN32_SOURCE = win32.cc
WINSVC_SOURCE = WinSvc.cc
else
WIN32_SOURCE =
WINSVC_SOURCE =
endif

if USE_IPC_WIN32
IPC_SOURCE = ipc_win32.cc
else
IPC_SOURCE = ipc.cc
endif

AIO_WIN32_ALL_SOURCES = \
	DiskIO/AIO/aio_win32.cc \
	DiskIO/AIO/aio_win32.h
if USE_AIO_WIN32
AIO_WIN32_SOURCES = $(AIO_WIN32_ALL_SOURCES)
else
AIO_WIN32_SOURCES =
endif

if USE_AIOPS_WIN32
AIOPS_SOURCE = DiskIO/DiskThreads/aiops_win32.cc
else
AIOPS_SOURCE = DiskIO/DiskThreads/aiops.cc
endif

IDENT_ALL_SOURCE = ACLIdent.cc ACLIdent.h ident.cc ident.h
if ENABLE_IDENT
IDENT_SOURCE = $(IDENT_ALL_SOURCE)
else
IDENT_SOURCE =
endif

ARP_ACL_ALL_SOURCE = ACLARP.cc ACLARP.h
if ENABLE_ARP_ACL
ARP_ACL_SOURCE = $(ARP_ACL_ALL_SOURCE)
else
ARP_ACL_SOURCE =
endif

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

EXTRA_LIBRARIES = libAIO.a libBlocking.a libDiskDaemon.a libDiskThreads.a
noinst_LIBRARIES = @DISK_LIBS@
noinst_LTLIBRARIES = libsquid.la libauth.la

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/lib/libTrie/include
INCLUDES        += -I$(top_builddir)/lib -I$(top_srcdir)/lib
INCLUDES	+= @SQUID_CPPUNIT_INC@

EXTRA_PROGRAMS = \
	DiskIO/DiskDaemon/diskd \
	unlinkd \
	pinger \
	dnsserver \
	recv-announce \
	tests/testUfs \
	tests/testCoss \
	tests/testNull

## cfgen is used when building squid
## ufsdump is a debug utility, it is possibly useful for end users with cache
## corruption, but at this point we do not install it.
noinst_PROGRAMS = \
	cf_gen \
	ufsdump

sbin_PROGRAMS = \
	squid

bin_PROGRAMS = 


libexec_PROGRAMS = \
	$(PINGER) \
	$(DNSSERVER) \
	@DISK_PROGRAMS@ \
	$(UNLINKD)

cf_gen_SOURCES = cf_gen.cc defines.h debug.cc time.cc
nodist_cf_gen_SOURCES = globals.cc
nodist_cf_gen_HEADER = cf_gen_defines.h
cf_gen.$(OBJEXT): cf_gen_defines.h

all_FSMODULES = \
	fs/aufs/StoreFSaufs.cc \
	fs/coss/StoreFScoss.cc \
	fs/diskd/StoreFSdiskd.cc \
	fs/ufs/StoreFSufs.cc

all_DISKIOMODULES = \
	DiskIO/AIO/AIODiskIOModule.cc \
	DiskIO/Blocking/BlockingDiskIOModule.cc \
	DiskIO/DiskDaemon/DiskDaemonDiskIOModule.cc \
	DiskIO/DiskThreads/DiskThreadsDiskIOModule.cc

DISKIO_SOURCE = \
	DiskIO/DiskIOModule.cc \
	DiskIO/ReadRequest.cc \
	DiskIO/ReadRequest.h \
	DiskIO/WriteRequest.cc \
	DiskIO/WriteRequest.h \
	DiskIO/DiskFile.h \
	DiskIO/DiskIOStrategy.h \
	DiskIO/IORequestor.h \
	DiskIO/DiskIOModule.h \
	DiskIO/ReadRequest.h

all_AUTHMODULES = \
	auth/basic/basicScheme.cc \
	auth/basic/basicScheme.h \
	auth/digest/digestScheme.cc \
	auth/digest/digestScheme.h \
	auth/ntlm/ntlmScheme.cc \
	auth/ntlm/ntlmScheme.h \
	auth/negotiate/negotiateScheme.cc \
	auth/negotiate/negotiateScheme.h 

EXTRA_squid_SOURCES = \
	$(all_FSMODULES) \
	$(all_DISKIOMODULES) \
	$(AIO_WIN32_ALL_SOURCES) \
	$(all_AUTHMODULES) \
	$(ARP_ACL_ALL_SOURCE) \
	ConfigOption.h \
	$(DELAY_POOL_ALL_SOURCE) \
	dns.cc \
	dnsserver.cc \
	dns_internal.cc \
	htcp.cc \
	htcp.h \
	ipc.cc \
	ipc_win32.cc \
	$(IDENT_ALL_SOURCE) \
	$(ESI_ALL_SOURCE) \
	ProfStats.cc \
	LeakFinder.cc \
	LeakFinder.h \
	$(SNMP_ALL_SOURCE) \
	$(UNLINKDSOURCE) \
	$(SSL_ALL_SOURCE) \
	$(WIN32_ALL_SOURCE) \
	$(LOADABLE_MODULES_SOURCES) \
	DiskIO/DiskThreads/aiops.cc \
	DiskIO/DiskThreads/aiops_win32.cc

squid_ACLSOURCES = \
	$(ARP_ACL_SOURCE) \
	ACLASN.cc \
	ACLASN.h \
	ACLDestinationASN.h \
	ACLSourceASN.h \
	ACLBrowser.cc \
	ACLBrowser.h \
	ACLData.h \
	ACLDestinationDomain.cc \
	ACLDestinationDomain.h \
	ACLDestinationIP.cc \
	ACLDestinationIP.h \
	ACLDomainData.h \
	ACLDomainData.cc \
	ACLExtUser.h \
	ACLExtUser.cc \
	ACLHTTPHeaderData.h \
	ACLHTTPHeaderData.cc \
	ACLHTTPStatus.h \
	ACLHTTPStatus.cc \
	ACLIntRange.cc \
	ACLIntRange.h \
	ACLIP.cc \
	ACLIP.h \
	ACLMaxConnection.cc \
	ACLMaxConnection.h \
	ACLMaxUserIP.cc \
	ACLMaxUserIP.h \
	ACLMethod.cc \
	ACLMethod.h \
	ACLMethodData.cc \
	ACLMethodData.h \
	ACLMyIP.cc \
	ACLMyIP.h \
	ACLMyPort.cc \
	ACLMyPort.h \
	ACLMyPortName.cc \
	ACLMyPortName.h \
	ACLProtocol.cc \
	ACLProtocol.h \
	ACLProtocolData.cc \
	ACLProtocolData.h \
	ACLProxyAuth.cc \
	ACLProxyAuth.h \
	ACLReferer.cc \
	ACLReferer.h \
	ACLRegexData.cc \
	ACLRegexData.h \
	ACLReplyHeaderStrategy.h \
	ACLReplyMIMEType.cc \
	ACLReplyMIMEType.h \
	ACLHTTPRepHeader.cc \
	ACLHTTPRepHeader.h \
	ACLHTTPReqHeader.cc \
	ACLHTTPReqHeader.h \
	ACLRequestHeaderStrategy.h \
	ACLRequestMIMEType.cc \
	ACLRequestMIMEType.h \
	ACLSourceDomain.cc \
	ACLSourceDomain.h \
	ACLSourceIP.cc \
	ACLSourceIP.h \
	ACLStrategised.cc \
	ACLStrategised.h \
	ACLStrategy.h \
	ACLStringData.cc \
	ACLStringData.h \
	ACLTime.cc \
	ACLTime.h \
	ACLTimeData.cc \
	ACLTimeData.h \
	ACLUrl.cc \
	ACLUrl.h \
	ACLUrlPath.cc \
	ACLUrlPath.h \
	ACLUrlPort.cc \
	ACLUrlPort.h \
	ACLUserData.cc \
	ACLUserData.h 

squid_COMMSOURCES = \
	comm_select.cc \
	comm_select.h \
	comm_select_win32.cc \
	comm_poll.cc \
	comm_poll.h \
	comm_epoll.cc \
	comm_epoll.h \
	comm_kqueue.cc \
	comm_kqueue.h


# common library for all the binaries and tests. This is kindof a catch all
# and smaller libraries split from this are encouraged. Using lt convenience
# libraries, dependencies should not be a problem either.
libsquid_la_SOURCES = \
	comm.cc \
	comm.h \
	CommCalls.cc \
	CommCalls.h \
	DescriptorSet.cc \
	DescriptorSet.h \
	IPInterception.cc \
	IPInterception.h \
        ICAP/AsyncJob.cc \
        ICAP/AsyncJob.h \
	SquidConfig.cc \
        TextException.cc \
        TextException.h


# authentication framework
libauth_la_SOURCES = \
	AuthConfig.cc \
	AuthConfig.h \
	AuthScheme.cc \
	AuthScheme.h \
	AuthUser.cc \
	AuthUserRequest.cc

squid_SOURCES = \
	access_log.cc \
	AccessLogEntry.h \
	acl.cc \
	acl_noncore.cc \
	ACL.h \
	ACLChecklist.cc \
	ACLChecklist.h \
	$(squid_ACLSOURCES) \
	asn.cc \
	AsyncCallQueue.cc \
	AsyncCallQueue.h \
	AsyncCall.cc \
	AsyncCall.h \
	AsyncJobCalls.h \
	AsyncEngine.cc \
	AsyncEngine.h \
	authenticate.cc \
	authenticate.h \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	CacheDigest.cc \
	cache_manager.cc \
	CacheManager.h \
	carp.cc \
	cbdata.cc \
	cbdata.h \
	ChunkedCodingParser.cc \
	ChunkedCodingParser.h \
	client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_reply.h \
	client_side_request.cc \
	client_side_request.h \
	BodyPipe.cc \
	BodyPipe.h \
	ClientRequestContext.h \
	clientStream.cc \
	clientStream.h \
	CommIO.h \
	CompletionDispatcher.cc \
	CompletionDispatcher.h \
	$(squid_COMMSOURCES) \
	CommRead.h \
	ConfigOption.cc \
	ConfigParser.cc \
	ConfigParser.h \
	ConnectionDetail.h \
	debug.cc \
	Debug.h \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	$(DISKIO_SOURCE) \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	enums.h \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	event.cc \
	event.h \
	EventLoop.h \
	EventLoop.cc \
	external_acl.cc \
	ExternalACL.h \
	ExternalACLEntry.cc \
	ExternalACLEntry.h \
	fd.cc \
	fde.cc \
	fde.h \
	filemap.cc \
	forward.cc \
	forward.h \
	fqdncache.cc \
	ftp.cc \
	Generic.h \
	globals.h \
	gopher.cc \
	helper.cc \
	helper.h \
	HierarchyLogEntry.h \
	$(HTCPSOURCE) \
	http.cc \
	http.h \
	HttpStatusLine.cc \
	HttpStatusLine.h \
	HttpHdrCc.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrSc.h \
	HttpHdrScTarget.cc \
	HttpHdrScTarget.h \
	HttpHdrContRange.cc \
	HttpHdrContRange.h \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderMask.h \
	HttpHeaderRange.h \
	HttpHeaderTools.cc \
	HttpBody.cc \
	HttpMsg.cc \
	HttpMsg.h \
	HttpReply.cc \
	HttpReply.h \
	HttpRequest.cc \
	HttpRequest.h \
	HttpRequestMethod.cc \
	HttpRequestMethod.h \
	HttpVersion.h \
	$(ICMPSOURCE) \
	ICP.h \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	int.cc \
	internal.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	$(LEAKFINDERSOURCE) \
	list.cc \
	logfile.cc \
	main.cc \
	mem.cc \
	mem_node.cc \
	mem_node.h \
	Mem.h \
	MemBuf.cc \
	MemObject.cc \
	MemObject.h \
	mime.cc \
	multicast.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Packer.h \
	Parsing.cc \
	Parsing.h \
	$(XPROF_STATS_SOURCE) \
	pconn.cc \
	pconn.h \
	PeerDigest.h \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	PeerSelectState.h \
	PingData.h \
	protos.h \
	redirect.cc \
	referer.cc \
	refresh.cc \
	RemovalPolicy.cc \
	RemovalPolicy.h \
	send-announce.cc \
	$(SNMP_SOURCE) \
	squid.h \
	SquidNew.cc \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	String.cc \
	stmem.cc \
	stmem.h \
	store.cc \
	Store.h \
	StoreFileSystem.cc \
	StoreFileSystem.h \
	StoreHashIndex.h \
	store_io.cc \
	StoreIOBuffer.h \
	StoreIOState.cc \
	StoreIOState.h \
	store_client.cc \
	StoreClient.h \
	store_digest.cc \
	store_dir.cc \
	store_key_md5.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreMeta.cc \
	StoreMeta.h \
	StoreMetaMD5.cc \
	StoreMetaMD5.h \
	StoreMetaSTD.cc \
	StoreMetaSTD.h \
	StoreMetaSTDLFS.cc \
	StoreMetaSTDLFS.h \
	StoreMetaObjSize.h \
	StoreMetaUnpacker.cc \
	StoreMetaUnpacker.h \
	StoreMetaURL.cc \
	StoreMetaURL.h \
	StoreMetaVary.cc \
	StoreMetaVary.h \
	StoreSearch.h \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	Server.cc \
	Server.h \
	structs.h \
	SwapDir.cc \
	SwapDir.h \
	time.cc \
	tools.cc \
	tunnel.cc \
	typedefs.h \
	$(UNLINKDSOURCE) \
	url.cc \
	URL.h \
	URLScheme.cc \
	URLScheme.h \
	urn.cc \
	useragent.cc \
	wccp.cc \
	wccp2.cc \
	whois.cc \
	wordlist.cc \
	wordlist.h \
	$(WIN32_SOURCE) \
	$(WINSVC_SOURCE)

noinst_HEADERS = ACLChecklist.cci \
	AuthUser.cci \
	AuthUser.h \
	AuthUserRequest.h \
	client_side_request.cci \
	MemBuf.cci \
	MemBuf.h \
	Store.cci \
	StoreEntryStream.h \
	String.cci \
	SquidString.h \
	SquidTime.h

nodist_squid_SOURCES = \
	repl_modules.cc \
	cf_parser.h \
	globals.cc \
	string_arrays.c

squid_LDADD = \
	libsquid.la \
	libauth.la \
	-L../lib \
	@XTRA_OBJS@ \
	@DISK_LINKOBJS@ \
	@REPL_OBJS@ \
	@STORE_LINKOBJS@ \
	@STORE_OBJS@ \
	@DISK_LIBS@ \
	@AUTH_LINKOBJS@ \
	@AUTH_OBJS@ \
	@CRYPTLIB@ \
	@REGEXLIB@ \
	@SNMPLIB@ \
	${ADAPTATION_LIBS} \
	@SSLLIB@ \
	-lmiscutil \
	@XTRA_LIBS@ \
	@EPOLL_LIBS@ \
	@MINGW_LIBS@ 
squid_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@STORE_OBJS@ \
	@STORE_LINKOBJS@ \
	@DISK_LIBS@ \
	@DISK_LINKOBJS@ \
	@REPL_OBJS@ \
	@AUTH_LINKOBJS@ \
	@AUTH_OBJS@

if USE_LOADABLE_MODULES
squid_SOURCES += $(LOADABLE_MODULES_SOURCES)
squid_LDADD += \
	@LIBLTDL@
squid_LDFLAGS = \
	-export-dynamic -dlopen force
# when static module linking is supported and enabled:
# squid_LDFLAGS = \
#         -all-static -dlopen self
#
endif


unlinkd_SOURCES = unlinkd_daemon.cc SquidNew.cc

## NP: the pinger contains the squid-external helper code
##     $(ICMPSOURCE) contains the interface bit to go inside squid
pinger_SOURCES = \
	ICMP.h \
	icmp.cc \
	ICMPPinger.h \
	ICMPPinger.cc \
	ICMPv4.h \
	ICMPv4.cc \
	ICMPv6.h \
	ICMPv6.cc \
	pinger.cc \
	debug.cc \
	time.cc \
	SquidNew.cc 

dnsserver_SOURCES = dnsserver.cc SquidNew.cc
recv_announce_SOURCES = recv-announce.cc SquidNew.cc

## What requires what..
## many things want ACLChecklist.cc
## ACLChecklist.cc wants AuthUserRequest.cc
## ACLChecklist.cc wants AuthScheme.cc
## ACLChecklist.cc wants ACLProxyAuth.cc directly
## ACLProxyAuth.cc wants ACLUserData
## ACLProxyAuth.cc wants ACLRegexData
## cache_cf.cc wants libauth.la
## cache_cf.cc wants Swapdir
## cache_cf.cc wants ProtoPort
## client_side wants client_db
## client_db wants SNMP_SOURCE
## snmp_core wants ACLStringData
## SwapDir wants ConfigOption
ufsdump_SOURCES = \
	debug.cc \
	int.cc \
	mem.cc \
	store_key_md5.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	String.cc \
	time.cc \
	ufsdump.cc \
	url.cc \
	AsyncCallQueue.cc \
	AsyncCallQueue.h \
	AsyncCall.cc \
	AsyncCall.h \
	BodyPipe.cc \
	BodyPipe.h \
	ConfigParser.cc \
	store.cc \
	StoreFileSystem.cc \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLUserData.cc \
	ACLRegexData.cc \
	ACLStringData.cc \
	authenticate.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	cache_manager.cc \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	ChunkedCodingParser.h \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	client_side_request.h \
	clientStream.cc \
	clientStream.h \
	CommIO.h \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	enums.h \
	errorpage.cc \
	errorpage.h \
	$(ESI_SOURCE) \
	ETag.cc \
	event.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	fde.h \
	filemap.cc \
	forward.cc \
	forward.h \
	fqdncache.cc \
	ftp.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpStatusLine.cc \
	HttpHdrCc.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHdrContRange.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpBody.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	internal.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	$(LEAKFINDERSOURCE) \
        list.cc \
	logfile.cc \
	mem_node.cc \
	mem_node.h \
	Mem.h \
	MemBuf.cc \
	MemObject.cc \
	MemObject.h \
	mime.cc \
	multicast.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Parsing.cc \
	$(XPROF_STATS_SOURCE) \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	protos.h \
	redirect.cc \
	referer.cc \
	refresh.cc \
	RemovalPolicy.cc \
	send-announce.cc \
	$(SNMP_SOURCE) \
	squid.h \
	$(SSL_SOURCE) \
	tunnel.cc \
	Server.cc \
	SquidNew.cc \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store_io.cc \
	StoreIOBuffer.h \
	StoreIOState.cc \
	store_client.cc \
	StoreClient.h \
	store_digest.cc \
	store_dir.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	structs.h \
	SwapDir.cc \
	tools.cc \
	typedefs.h \
	$(UNLINKDSOURCE) \
	URLScheme.cc \
	urn.cc \
	useragent.cc \
	wccp.cc \
	wccp2.cc \
	whois.cc \
	wordlist.cc \
	$(WIN32_SOURCE)
ufsdump_LDADD = \
	libsquid.la \
	libauth.la \
	-L../lib \
	@XTRA_OBJS@ \
	@REPL_OBJS@ \
	@STORE_OBJS@ \
	@AUTH_OBJS@ \
	@CRYPTLIB@ \
	@REGEXLIB@ \
	@SNMPLIB@ \
	${ADAPTATION_LIBS} \
	@SSLLIB@ \
	-lmiscutil \
	@XTRA_LIBS@ \
	@EPOLL_LIBS@ \
	@MINGW_LIBS@ 
ufsdump_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@STORE_OBJS@ \
	@STORE_LINKOBJS@ \
	@DISK_LIBS@ \
	@DISK_LINKOBJS@ \
	@REPL_OBJS@ \
	@AUTH_LINKOBJS@ \
	@AUTH_OBJS@

nodist_ufsdump_SOURCES = \
	repl_modules.cc \
	cf_parser.h \
	globals.cc \
	string_arrays.c

nodist_pinger_SOURCES = \
	globals.cc

BUILT_SOURCES = \
	cf_gen_defines.h \
	cf_parser.h \
	globals.cc \
	string_arrays.c \
	repl_modules.cc

sysconf_DATA = \
	squid.conf.default \
	squid.conf.documented \
	mime.conf.default

data_DATA = \
	mib.txt

LDADD = libsquid.la libauth.la -L../lib -lmiscutil @XTRA_LIBS@ @EPOLL_LIBS@ @MINGW_LIBS@

EXTRA_DIST = \
	cf_gen_defines \
	cf.data.pre \
	cf.data.depend \
	mk-globals-c.pl \
	mk-globals-c.awk \
	mk-string-arrays.pl \
	mk-string-arrays.awk \
	repl_modules.sh \
	mib.txt \
	mime.conf.default

libAIO_a_SOURCES = \
		$(AIO_WIN32_SOURCES) \
		DiskIO/AIO/async_io.h \
		DiskIO/AIO/AIODiskFile.cc \
		DiskIO/AIO/AIODiskFile.h \
		DiskIO/AIO/AIODiskIOStrategy.cc \
		DiskIO/AIO/AIODiskIOStrategy.h \
		DiskIO/AIO/AIODiskIOModule.h 

libBlocking_a_SOURCES = \
		DiskIO/Blocking/BlockingFile.cc \
		DiskIO/Blocking/BlockingFile.h \
		DiskIO/Blocking/BlockingIOStrategy.cc \
		DiskIO/Blocking/BlockingIOStrategy.h \
		DiskIO/Blocking/BlockingDiskIOModule.h 

libDiskDaemon_a_SOURCES = \
		DiskIO/DiskDaemon/DiskdFile.cc \
		DiskIO/DiskDaemon/DiskdFile.h \
		DiskIO/DiskDaemon/DiskdIOStrategy.cc \
		DiskIO/DiskDaemon/DiskdIOStrategy.h \
		DiskIO/DiskDaemon/diomsg.h \
		DiskIO/DiskDaemon/DiskDaemonDiskIOModule.h

libDiskThreads_a_SOURCES = \
		$(AIOPS_SOURCE) \
		DiskIO/DiskThreads/async_io.cc \
		DiskIO/DiskThreads/DiskThreads.h \
		DiskIO/DiskThreads/DiskThreadsDiskFile.cc \
		DiskIO/DiskThreads/DiskThreadsDiskFile.h \
		DiskIO/DiskThreads/DiskThreadsDiskIOModule.h \
		DiskIO/DiskThreads/DiskThreadsIOStrategy.cc \
		DiskIO/DiskThreads/DiskThreadsIOStrategy.h

DiskIO_DiskDaemon_diskd_SOURCES = DiskIO/DiskDaemon/diskd.cc 
DiskIO_DiskDaemon_diskd_LDADD = $(top_builddir)/lib/libmiscutil.a @XTRA_LIBS@


DEFAULT_HTTP_PORT	= @CACHE_HTTP_PORT@
DEFAULT_ICP_PORT	= @CACHE_ICP_PORT@
DEFAULT_PREFIX		= $(prefix)
DEFAULT_CONFIG_FILE     = $(sysconfdir)/squid.conf
DEFAULT_MIME_TABLE	= $(sysconfdir)/mime.conf
DEFAULT_DNSSERVER       = $(libexecdir)/`echo dnsserver | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_LOG_PREFIX	= @DEFAULT_LOG_DIR@
DEFAULT_CACHE_LOG       = $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG      = $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG       = $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_PID_FILE        = $(DEFAULT_LOG_PREFIX)/squid.pid
DEFAULT_NETDB_FILE      = $(DEFAULT_LOG_PREFIX)/netdb.state
DEFAULT_SWAP_DIR        = $(localstatedir)/cache
DEFAULT_PINGER		= $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_UNLINKD		= $(libexecdir)/`echo unlinkd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_DISKD		= $(libexecdir)/`echo diskd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_ICON_DIR	= $(datadir)/icons
DEFAULT_ERROR_DIR	= $(datadir)/errors
DEFAULT_MIB_PATH	= $(datadir)/mib.txt
DEFAULT_HOSTS		= @OPT_DEFAULT_HOSTS@

DEFS = @DEFS@ -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\"

$(OBJS): $(top_srcdir)/include/version.h ../include/autoconf.h

snmp_core.o snmp_agent.o: ../snmplib/libsnmp.a $(top_srcdir)/include/cache_snmp.h

globals.cc: globals.h mk-globals-c.pl
	$(AWK) -f $(srcdir)/mk-globals-c.awk < $(srcdir)/globals.h > $@

string_arrays.c: enums.h mk-string-arrays.pl
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/enums.h > $@

cache_diff: cache_diff.o debug.o globals.o store_key_md5.o
	$(CC) -o $@ $(LDFLAGS) $@.o debug.o globals.o store_key_md5.o $(STD_APP_LIBS)

test_cache_digest: test_cache_digest.o CacheDigest.o debug.o globals.o store_key_md5.o
	$(CC) -o $@ $(LDFLAGS) $@.o CacheDigest.o debug.o globals.o store_key_md5.o $(STD_APP_LIBS)

## If autodependency works well this is not needed anymore
cache_cf.o: cf_parser.h

# squid.conf.default is built by cf_gen when making cf_parser.h
squid.conf.documented: cf_parser.h
	true

squid.conf.default: squid.conf.documented
	grep -v -E "^[#\ ]" squid.conf.documented | grep . >squid.conf.default

cf_parser.h: cf.data cf_gen$(EXEEXT)
	./cf_gen cf.data $(srcdir)/cf.data.depend

cf_gen_defines.h: $(srcdir)/cf_gen_defines $(srcdir)/cf.data.pre
	$(AWK) -f $(srcdir)/cf_gen_defines <$(srcdir)/cf.data.pre >cf_gen_defines.h


## FIXME: generate a sed command file from configure. Then this doesn't
## depend on the Makefile.
cf.data: cf.data.pre Makefile
	sed "\
	s%@DEFAULT_HTTP_PORT@%$(DEFAULT_HTTP_PORT)%g;\
	s%@DEFAULT_ICP_PORT@%$(DEFAULT_ICP_PORT)%g;\
	s%@DEFAULT_CACHE_EFFECTIVE_USER@%${CACHE_EFFECTIVE_USER}%g;\
	s%@DEFAULT_MIME_TABLE@%$(DEFAULT_MIME_TABLE)%g;\
	s%@DEFAULT_DNSSERVER@%$(DEFAULT_DNSSERVER)%g;\
	s%@DEFAULT_UNLINKD@%$(DEFAULT_UNLINKD)%g;\
	s%@DEFAULT_PINGER@%$(DEFAULT_PINGER)%g;\
	s%@DEFAULT_DISKD@%$(DEFAULT_DISKD)%g;\
	s%@DEFAULT_CACHE_LOG@%$(DEFAULT_CACHE_LOG)%g;\
	s%@DEFAULT_ACCESS_LOG@%$(DEFAULT_ACCESS_LOG)%g;\
	s%@DEFAULT_STORE_LOG@%$(DEFAULT_STORE_LOG)%g;\
	s%@DEFAULT_PID_FILE@%$(DEFAULT_PID_FILE)%g;\
	s%@DEFAULT_NETDB_FILE@%$(DEFAULT_NETDB_FILE)%g;\
	s%@DEFAULT_SWAP_DIR@%$(DEFAULT_SWAP_DIR)%g;\
	s%@DEFAULT_ICON_DIR@%$(DEFAULT_ICON_DIR)%g;\
	s%@DEFAULT_MIB_PATH@%$(DEFAULT_MIB_PATH)%g;\
	s%@DEFAULT_ERROR_DIR@%$(DEFAULT_ERROR_DIR)%g;\
	s%@DEFAULT_PREFIX@%$(DEFAULT_PREFIX)%g;\
	s%@DEFAULT_HOSTS@%$(DEFAULT_HOSTS)%g;\
	s%@[V]ERSION@%$(VERSION)%g;"\
	< $(srcdir)/cf.data.pre >$@

repl_modules.cc: repl_modules.sh Makefile
	$(SHELL) $(srcdir)/repl_modules.sh $(REPL_POLICIES) > repl_modules.cc

install-data-local: install-sysconfDATA install-dataDATA
	@if test -f $(DESTDIR)$(DEFAULT_MIME_TABLE) ; then \
	        echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_MIME_TABLE)" ; \
	else \
	        echo "$(INSTALL_DATA) $(srcdir)/mime.conf.default $(DESTDIR)$(DEFAULT_MIME_TABLE)" ;\
	        $(INSTALL_DATA) $(srcdir)/mime.conf.default $(DESTDIR)$(DEFAULT_MIME_TABLE); \
	fi
	@if test -f $(DESTDIR)$(DEFAULT_CONFIG_FILE) ; then \
	        echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_CONFIG_FILE)" ; \
	else \
	        echo "$(INSTALL_DATA) squid.conf.default $(DESTDIR)$(DEFAULT_CONFIG_FILE)"; \
	        $(INSTALL_DATA) squid.conf.default $(DESTDIR)$(DEFAULT_CONFIG_FILE); \
	fi
	echo "$(INSTALL_DATA) squid.conf.default $(DESTDIR)$(DEFAULT_CONFIG_FILE).default"; \
	$(INSTALL_DATA) squid.conf.default $(DESTDIR)$(DEFAULT_CONFIG_FILE).default; \
	echo "$(INSTALL_DATA) squid.conf.documented $(DESTDIR)$(DEFAULT_CONFIG_FILE).documented"; \
	$(INSTALL_DATA) squid.conf.documented $(DESTDIR)$(DEFAULT_CONFIG_FILE).documented; \
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_LOG_PREFIX)

uninstall-local:
	@if test -f $(DESTDIR)$(DEFAULT_MIME_TABLE) ; then \
		echo "rm -f $(DESTDIR)$(DEFAULT_MIME_TABLE)"; \
		$(RM) -f $(DESTDIR)$(DEFAULT_MIME_TABLE); \
	fi

# Don't automatically uninstall config files
#	@if test -f $(DESTDIR)$(DEFAULT_CONFIG_FILE) ; then \
#		echo "rm -f $(DESTDIR)$(DEFAULT_CONFIG_FILE)"; \
#		$(RM) -f $(DESTDIR)$(DEFAULT_CONFIG_FILE); \
#	fi

DISTCLEANFILES = cf_gen_defines.h cf.data cf_parser.h squid.conf.default squid.conf.documented \
	globals.cc string_arrays.c repl_modules.cc 

##install-pinger:
##	@f=$(PINGER_EXE); \
##	if test -f $(libexecdir)/$$f; then \
##		echo $(MV) $(libexecdir)/$$f $(libexecdir)/-$$f; \
##		$(MV) $(libexecdir)/$$f $(libexecdir)/-$$f; \
##	fi; \
##	echo $(INSTALL_SUID) $$f $(libexecdir); \
##	$(INSTALL_SUID) $$f $(libexecdir) || exit 1; \
##	if test -f $(libexecdir)/-$$f; then \
##		echo $(RM) -f $(libexecdir)/-$$f; \
##		$(RM) -f $(libexecdir)/-$$f; \
##	fi

# stock tools for unit tests - library independent versions of dlink_list 
# etc.
# globals.cc is needed by test_tools.cc
TESTSOURCES= \
	../test-suite/test_tools.cc \
	globals.cc

# sources needed by those tests that need event.cc; incomplete
TEST_CALL_SOURCES = \
	event.cc \
	AsyncCallQueue.cc \
	AsyncCall.cc


check_PROGRAMS+= tests/testAuth \
	tests/testACLMaxUserIP \
	tests/testBoilerplate \
	tests/testCacheManager \
	tests/testDiskIO \
	tests/testEvent \
	tests/testEventLoop \
	tests/test_http_range \
	tests/testHttpRequest \
	tests/testICMP \
	tests/testStore \
	tests/testString \
	tests/testURL \
	@STORE_TESTS@

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/*.h $(top_srcdir)/src/DiskIO/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "." || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "DiskIO" || exit 1
## src/repl/ has no .h files and its own makefile.

## No such file...
testHeaders.c:
	touch testHeaders.c

### Template for new Unit Test Program
## - add tests/testX to check_PROGRAMS above.
## - copy template below and substitue X for class name
## - add other component .(h|cc) files needed to link and run tests
##
##NP: (TESTSOURCES) defines stub debugs() and new/delete for testing
##
#tests_testX_SOURCES=\
#	tests/testX.h \
#	tests/testX.cc \
#	tests/testMain.cc \
#	X.h \
#	X.cc \
#	$(TESTSOURCES)
#tests_testX_LDFLAGS = $(LIBADD_DL)
#tests_testX_LDADD=\
#	@SQUID_CPPUNIT_LIBS@ \
#	@SQUID_CPPUNIT_LA@ \
#	-L../lib -lmiscutil
#tests_testX_DEPENDENCIES= @SQUID_CPPUNIT_LA@ \
#	$(top_builddir)/lib/libmiscutil.a

tests_testAuth_SOURCES= tests/testAuth.cc tests/testMain.cc  tests/testAuth.h $(TESTSOURCES) \
	authenticate.cc \
	ConfigParser.cc \
	tests/stub_acl.cc tests/stub_cache_cf.cc \
	tests/stub_helper.cc cbdata.cc String.cc \
	tests/stub_store.cc HttpHeaderTools.cc HttpHeader.cc acl.cc mem.cc \
	MemBuf.cc HttpHdrContRange.cc Packer.cc ACLChecklist.cc HttpHdrCc.cc HttpHdrSc.cc \
	HttpHdrScTarget.cc url.cc ACLProxyAuth.cc ACLRegexData.cc ACLUserData.cc \
	StatHist.cc HttpHdrRange.cc ETag.cc tests/stub_errorpage.cc \
	tests/stub_HttpRequest.cc tests/stub_DelayId.cc \
	tests/stub_MemObject.cc mem_node.cc \
	tests/stub_cache_manager.cc \
	stmem.cc \
	tests/stub_comm.cc \
	tests/stub_http.cc \
	HttpMsg.cc \
	HttpRequestMethod.cc \
	tests/stub_mime.cc \
	tests/stub_access_log.cc \
	time.cc \
	URLScheme.cc \
	$(TEST_CALL_SOURCES) \
	wordlist.cc
##	acl.cc cache_cf.cc tools.cc \
##	helper.cc String.cc cbdata.cc HttpHeaderTools.cc store.cc cache_manager.cc \
##	HttpHeader.cc url.cc mem.cc HttpRequest.cc Packer.cc access_log.cc \
##	MemBuf.cc StatHist.cc logfile.cc

tests_testAuth_LDADD= \
	libsquid.la \
	libauth.la \
	@AUTH_LINKOBJS@ @AUTH_OBJS@ \
	-L../lib -lmiscutil \
	@REGEXLIB@ \
	@SQUID_CPPUNIT_LIBS@ \
	@SSLLIB@
tests_testAuth_LDFLAGS = $(LIBADD_DL)
tests_testAuth_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@AUTH_LINKOBJS@ \
	@AUTH_OBJS@ \
	@SQUID_CPPUNIT_LA@

## Tests for the ACLMaxUserIP class
## acl needs wordlist. wordlist needs MemBug
## MemBuf needs mem, MemBuf needs event,
## event needs cbdata.
## ACLMaxUserUP needs authenticate.cc
## authenticate.cc needs libauth.la
## ACLMaxUserIP needs ACLChecklist
## AuthUser request needs HttpHeader, which brings in 
##	ETag.cc \
##	HttpHeader.cc \
##	HttpHeaderTools.cc \
##	HttpHdrContRange.cc \
##	HttpHdrCc.cc \
##	HttpHdrRange.cc \
##	HttpHdrSc.cc \
##	HttpHdrScTarget.cc \
##	Packer.cc \
##	StatHist.cc \
##	String.cc \
tests_testACLMaxUserIP_SOURCES= \
	acl.cc \
	ACLChecklist.cc \
	ACLMaxUserIP.cc \
	ACLProxyAuth.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	cbdata.cc \
	ConfigParser.cc \
	ETag.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrCc.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	mem_node.cc \
	Packer.cc \
	Parsing.cc \
	StatHist.cc \
	stmem.cc \
	String.cc \
	$(TEST_CALL_SOURCES) \
	$(TESTSOURCES) \
	tests/stub_cache_cf.cc \
	tests/stub_comm.cc \
	tests/stub_DelayId.cc \
	tests/stub_MemObject.cc \
	tests/stub_store.cc \
	tests/stub_cache_manager.cc \
	tests/testACLMaxUserIP.cc \
	tests/testACLMaxUserIP.h \
	tests/testMain.cc \
	time.cc \
	mem.cc \
	MemBuf.cc \
	wordlist.cc
tests_testACLMaxUserIP_LDADD= \
	libsquid.la \
	libauth.la \
	-L../lib -lmiscutil \
	@REGEXLIB@ \
	@SQUID_CPPUNIT_LIBS@ \
	@SSLLIB@
tests_testACLMaxUserIP_LDFLAGS = $(LIBADD_DL)
tests_testACLMaxUserIP_DEPENDENCIES = \
	@SQUID_CPPUNIT_LA@

## a demonstration test that does nothing but shows the salient points
## involved in writing tests.
tests_testBoilerplate_SOURCES = \
	tests/testBoilerplate.cc \
	tests/testMain.cc \
	tests/testBoilerplate.h \
	$(TESTSOURCES) \
	time.cc
tests_testBoilerplate_LDADD= \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SSLLIB@
tests_testBoilerplate_LDFLAGS = $(LIBADD_DL)
tests_testBoilerplate_DEPENDENCIES = \
	@SQUID_CPPUNIT_LA@

## Tests of the CacheManager module.
tests_testCacheManager_SOURCES = \
	debug.cc \
	globals.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	mem.cc \
	String.cc \
	tests/testCacheManager.cc \
	tests/testCacheManager.h \
	tests/testMain.cc \
	time.cc \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLStringData.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	clientStream.cc \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.cc \
	internal.cc \
	list.cc \
	logfile.cc \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	redirect.cc \
	referer.cc \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	$(TEST_CALL_SOURCES) \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	url.cc \
	URLScheme.cc \
	urn.cc \
	useragent.cc \
	wccp2.cc \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.cc
nodist_tests_testCacheManager_SOURCES = \
	repl_modules.cc \
	string_arrays.c
tests_testCacheManager_LDADD = \
	libsquid.la \
	libauth.la \
	@REPL_OBJS@ \
	${ADAPTATION_LIBS} \
	@REGEXLIB@ \
	@SNMPLIB@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	@SSLLIB@ \
	@XTRA_LIBS@
tests_testCacheManager_LDFLAGS = $(LIBADD_DL)
tests_testCacheManager_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	@REPL_OBJS@ \
	@SQUID_CPPUNIT_LA@

tests_testDiskIO_SOURCES= \
	$(SWAP_TEST_SOURCES) \
	tests/testDiskIO.cc \
	tests/testDiskIO.h \
	tests/testMain.cc \
	tests/stub_cache_manager.cc

tests_testDiskIO_LDADD= \
	$(SWAP_TEST_LDADD) \
	libsquid.la \
	@SSLLIB@
tests_testDiskIO_LDFLAGS = $(LIBADD_DL)
tests_testDiskIO_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@SQUID_CPPUNIT_LA@

## Tests of the Even module.
tests_testEvent_SOURCES = \
	debug.cc \
	EventLoop.h \
	EventLoop.cc \
	globals.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	mem.cc \
	RemovalPolicy.cc \
	String.cc \
	tests/CapturingStoreEntry.h \
	tests/testEvent.cc \
	tests/testEvent.h \
	tests/testMain.cc \
	time.cc \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLStringData.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	clientStream.cc \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.cc \
	internal.cc \
	list.cc \
	logfile.cc \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	redirect.cc \
	referer.cc \
	refresh.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	$(TEST_CALL_SOURCES) \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	url.cc \
	URLScheme.cc \
	urn.cc \
	useragent.cc \
	wccp2.cc \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.cc
nodist_tests_testEvent_SOURCES = \
	repl_modules.cc \
	string_arrays.c
tests_testEvent_LDADD = \
	libsquid.la \
	libauth.la \
	@REPL_OBJS@ \
	${ADAPTATION_LIBS} \
	@REGEXLIB@ \
	@SNMPLIB@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	@SSLLIB@ \
	@XTRA_LIBS@
tests_testEvent_LDFLAGS = $(LIBADD_DL)
tests_testEvent_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	@REPL_OBJS@ \
	@SQUID_CPPUNIT_LA@

## Tests of the EventLoop module.
tests_testEventLoop_SOURCES = \
	debug.cc \
	EventLoop.h \
	EventLoop.cc \
	globals.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	mem.cc \
	RemovalPolicy.cc \
	String.cc \
	tests/testEventLoop.cc \
	tests/testEventLoop.h \
	tests/testMain.cc \
	time.cc \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLStringData.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	clientStream.cc \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.cc \
	internal.cc \
	list.cc \
	logfile.cc \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	redirect.cc \
	referer.cc \
	refresh.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	$(TEST_CALL_SOURCES) \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	url.cc \
	URLScheme.cc \
	urn.cc \
	useragent.cc \
	wccp2.cc \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.cc
nodist_tests_testEventLoop_SOURCES = \
	repl_modules.cc \
	string_arrays.c
tests_testEventLoop_LDADD = \
	libsquid.la \
	libauth.la \
	@REPL_OBJS@ \
	${ADAPTATION_LIBS} \
	@REGEXLIB@ \
	@SNMPLIB@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	@SSLLIB@ \
	@XTRA_LIBS@
tests_testEventLoop_LDFLAGS = $(LIBADD_DL)
tests_testEventLoop_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	@REPL_OBJS@ \
	@SQUID_CPPUNIT_LA@

tests_test_http_range_SOURCES = \
	tests/test_http_range.cc \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLStringData.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	BodyPipe.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	cache_manager.cc \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	clientStream.cc \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	ConfigParser.cc \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	globals.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	int.cc \
	internal.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	list.cc \
	logfile.cc \
	mem.cc \
	mem_node.cc \
	MemObject.cc \
	mime.cc \
	multicast.cc \
	neighbors.cc \
	net_db.cc \
	Parsing.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	pconn.cc \
	redirect.cc \
	referer.cc \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_dir.cc \
	store_key_md5.cc \
	store_io.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	String.cc \
	SwapDir.cc \
	$(TEST_CALL_SOURCES) \
	time.cc \
	tools.cc \
	tunnel.cc \
	url.cc \
	URLScheme.cc \
	urn.cc \
	useragent.cc \
	wccp2.cc \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.cc \
	Packer.cc \
	MemBuf.cc
nodist_tests_test_http_range_SOURCES = \
	repl_modules.cc \
	string_arrays.c
tests_test_http_range_LDADD = \
	libsquid.la \
	libauth.la \
	@REPL_OBJS@ \
	@STORE_OBJS@ \
	${ADAPTATION_LIBS} \
	@REGEXLIB@ \
	@SNMPLIB@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	@SSLLIB@ \
	@XTRA_LIBS@
tests_test_http_range_LDFLAGS = $(LIBADD_DL)
tests_test_http_range_DEPENDENCIES = \
	@SQUID_CPPUNIT_LA@


## Tests of the HttpRequest module.
tests_testHttpRequest_SOURCES = \
	debug.cc \
	globals.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	mem.cc \
	String.cc \
	tests/testHttpRequest.h \
	tests/testHttpRequest.cc \
	tests/testHttpRequestMethod.h \
	tests/testHttpRequestMethod.cc \
	tests/testMain.cc \
	time.cc \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLStringData.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	clientStream.cc \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.cc \
	internal.cc \
	list.cc \
	logfile.cc \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	redirect.cc \
	referer.cc \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	$(TEST_CALL_SOURCES) \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	url.cc \
	URLScheme.cc \
	urn.cc \
	useragent.cc \
	wccp2.cc \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.cc
nodist_tests_testHttpRequest_SOURCES = \
	repl_modules.cc \
	string_arrays.c
tests_testHttpRequest_LDADD = \
	libsquid.la \
	libauth.la \
	@REPL_OBJS@ \
	${ADAPTATION_LIBS} \
	@REGEXLIB@ \
	@SNMPLIB@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	@SSLLIB@ \
	@XTRA_LIBS@
tests_testHttpRequest_LDFLAGS = $(LIBADD_DL)
tests_testHttpRequest_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	@REPL_OBJS@ \
	@SQUID_CPPUNIT_LA@

## Tests of the ICMP base module.
# Its used by pinger so SHOULD NOT require more dependancies! :-(
tests_testICMP_SOURCES=\
	ICMP.h \
	icmp.cc \
	tests/testICMP.h \
	tests/testICMP.cc \
	tests/testMain.cc \
	SquidTime.h \
	time.cc \
	$(TESTSOURCES)
tests_testICMP_LDFLAGS = $(LIBADD_DL)
tests_testICMP_LDADD=\
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	-L../lib -lmiscutil
tests_testICMP_DEPENDENCIES= @SQUID_CPPUNIT_LA@ \
	$(top_builddir)/lib/libmiscutil.a

# TODO:mime.cc drags in HttpReply.cc
# delay pools need client_side_request.cc
# store_key_md5 wants the method.
STORE_TEST_SOURCES=\
	$(TESTSOURCES) \
	$(TEST_CALL_SOURCES) \
	$(DELAY_POOL_SOURCE) \
	CacheDigest.cc \
	ConfigParser.cc \
	EventLoop.cc \
	HttpMsg.cc \
	RemovalPolicy.cc \
	store_dir.cc \
	store.cc \
	HttpRequestMethod.cc \
	store_key_md5.cc \
	string_arrays.c \
	Parsing.cc \
	ConfigOption.cc \
	SwapDir.cc \
	authenticate.cc \
	tests/stub_acl.cc tests/stub_cache_cf.cc \
	tests/stub_helper.cc cbdata.cc String.cc \
	tests/stub_comm.cc \
	tests/stub_client_side_request.cc \
	tests/stub_http.cc \
	mem_node.cc \
	stmem.cc \
	tests/stub_mime.cc \
	HttpHeaderTools.cc HttpHeader.cc acl.cc mem.cc \
	acl_noncore.cc \
	MemBuf.cc HttpHdrContRange.cc Packer.cc ACLChecklist.cc HttpHdrCc.cc HttpHdrSc.cc \
	HttpHdrScTarget.cc url.cc ACLProxyAuth.cc ACLRegexData.cc ACLUserData.cc \
	StatHist.cc HttpHdrRange.cc ETag.cc tests/stub_errorpage.cc \
	tests/stub_HttpRequest.cc tests/stub_access_log.cc \
	refresh.cc \
	tests/stub_store_client.cc \
	tests/stub_tools.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	time.cc \
	URLScheme.cc \
	wordlist.cc

## why so many sources? well httpHeaderTools requites ACLChecklist & friends.
## first line - what we are testing.
tests_testStore_SOURCES= \
	tests/stub_store_swapout.cc \
	tests/testMain.cc \
	tests/stub_MemObject.cc \
	tests/testStore.cc \
	tests/testStore.h \
	tests/CapturingStoreEntry.h \
	tests/testStoreEntryStream.cc \
	tests/testStoreEntryStream.h \
	tests/testStoreController.cc \
	tests/testStoreController.h \
	tests/testStoreHashIndex.cc \
	tests/testStoreHashIndex.h \
	tests/TestSwapDir.cc \
	tests/TestSwapDir.h \
	tests/stub_fd.cc \
	tests/stub_HttpReply.cc \
	tests/stub_cache_manager.cc \
	$(STORE_TEST_SOURCES)

tests_testStore_LDADD= \
	libsquid.la \
	libauth.la \
	-L../lib -lmiscutil \
	@REGEXLIB@ \
	@SQUID_CPPUNIT_LIBS@ \
	@SSLLIB@
tests_testStore_LDFLAGS = $(LIBADD_DL)
tests_testStore_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@SQUID_CPPUNIT_LA@

# string needs mem.cc.
tests_testString_SOURCES= \
	mem.cc \
	String.cc \
	tests/testMain.cc \
	tests/testString.cc \
	tests/testString.h \
	tests/stub_cache_manager.cc \
	$(TESTSOURCES) \
	time.cc 

tests_testString_LDADD= \
	libsquid.la \
	-L../lib -lmiscutil \
	@REGEXLIB@ \
	@SQUID_CPPUNIT_LIBS@ \
	@SSLLIB@
tests_testString_LDFLAGS = $(LIBADD_DL)
tests_testString_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@SQUID_CPPUNIT_LA@

SWAP_TEST_SOURCES = \
	tests/stub_store_rebuild.cc \
	tests/stub_internal.cc \
	fd.cc \
	disk.cc \
	filemap.cc \
	HttpBody.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	int.cc \
	list.cc \
	MemObject.cc \
	StoreSwapLogData.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreFileSystem.cc \
	store_io.cc \
	store_swapout.cc \
	store_swapmeta.cc \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	$(STORE_TEST_SOURCES) \
	$(DISKIO_SOURCE)

SWAP_TEST_LDADD = \
	libauth.la \
	DiskIO/Blocking/BlockingDiskIOModule.o \
	repl/lru/store_repl_lru.o \
	@REGEXLIB@ \
	@STORE_LINKOBJS@ \
	@STORE_OBJS@ \
	@REPL_OBJS@ \
	@DISK_LIBS@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@
SWAP_TEST_DS =\
	$(top_builddir)/lib/libmiscutil.a \
	DiskIO/Blocking/BlockingDiskIOModule.o \
	repl/lru/store_repl_lru.o \
	repl_modules.o \
	@DISK_LIBS@ \
	@STORE_LINKOBJS@ \
	@STORE_OBJS@ \
	@REPL_OBJS@ \
	@SQUID_CPPUNIT_LA@

tests_testUfs_SOURCES= tests/testUfs.cc \
	tests/testMain.cc \
	tests/testUfs.h \
	tests/stub_cache_manager.cc \
	$(SWAP_TEST_SOURCES)
tests_testUfs_LDADD= \
	libsquid.la \
	$(SWAP_TEST_LDADD) \
	@SSLLIB@
tests_testUfs_LDFLAGS = $(LIBADD_DL)
tests_testUfs_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testCoss_SOURCES= tests/testCoss.cc \
	tests/testMain.cc \
	tests/testCoss.h \
	tests/stub_cache_manager.cc \
	$(SWAP_TEST_SOURCES)
tests_testCoss_LDADD= \
	libsquid.la \
	$(SWAP_TEST_LDADD) \
	@SSLLIB@
tests_testCoss_LDFLAGS = $(LIBADD_DL)
tests_testCoss_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testNull_SOURCES= tests/testNull.cc \
	tests/testMain.cc \
	tests/testNull.h \
	$(SWAP_TEST_SOURCES)
tests_testNull_LDADD= \
	$(SWAP_TEST_LDADD) \
	@SSLLIB@
tests_testNull_LDFLAGS = $(LIBADD_DL)
tests_testNull_DEPENDENCIES = \
	$(SWAP_TEST_DS)

## Tests of the URL module.
## TODO: Trim this down once the insanity is over.
tests_testURL_SOURCES = \
	debug.cc \
	url.cc \
	URLScheme.cc \
	globals.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	mem.cc \
	RemovalPolicy.cc \
	String.cc \
	tests/testURL.cc \
	tests/testURL.h \
	tests/testURLScheme.cc \
	tests/testURLScheme.h \
	tests/testMain.cc \
	time.cc \
	access_log.cc \
	acl.cc \
	acl_noncore.cc \
	ACLChecklist.cc \
	ACLProxyAuth.cc \
	ACLStringData.cc \
	ACLRegexData.cc \
	ACLUserData.cc \
	authenticate.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.cc \
	ProtoPort.cc \
	ProtoPort.h \
	CacheDigest.cc \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	clientStream.cc \
	$(squid_COMMSOURCES) \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	$(ICMPSOURCE) \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.cc \
	internal.cc \
	list.cc \
	logfile.cc \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.cc \
	neighbors.cc \
	net_db.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_userhash.cc \
	redirect.cc \
	referer.cc \
	refresh.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	$(SSL_SOURCE) \
	stat.cc \
	StatHist.cc \
	stmem.cc \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.cc \
	store_log.cc \
	store_rebuild.cc \
	store_swapin.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	$(TEST_CALL_SOURCES) \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	urn.cc \
	useragent.cc \
	wccp2.cc \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.cc
nodist_tests_testURL_SOURCES = \
	repl_modules.cc \
	string_arrays.c
tests_testURL_LDADD = \
	libsquid.la \
	libauth.la \
	@REGEXLIB@ \
	@REPL_OBJS@ \
	${ADAPTATION_LIBS} \
	@SNMPLIB@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LIBS@ \
	@SQUID_CPPUNIT_LA@ \
	@SSLLIB@ \
	@XTRA_LIBS@
tests_testURL_LDFLAGS = $(LIBADD_DL)
tests_testURL_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	@REPL_OBJS@ \
	@SQUID_CPPUNIT_LA@
