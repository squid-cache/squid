#
#  Makefile for the Squid Object Cache server
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects

if ENABLE_DNSHELPER
DNSSOURCE = dns.cc
DNSHELPER = dnsserver
else
DNSSOURCE = dns_internal.cc
DNSHELPER =
endif

DNSSOURCE += \
	SquidDns.h \
	DnsLookupDetails.h \
	DnsLookupDetails.cc

SBUF_SOURCE= \
	base/InstanceId.h \
	MemBlob.h \
	MemBlob.cc

LOADABLE_MODULES_SOURCES = \
	LoadableModule.h \
	LoadableModule.cc \
	LoadableModules.h \
	LoadableModules.cc

SUBDIRS	= base anyp comm eui acl format fs repl
DIST_SUBDIRS = base anyp comm eui acl format fs repl

if ENABLE_AUTH
SUBDIRS += auth
AUTH_LIBS= auth/libauth.la
AUTH_ACL_LIBS= auth/libacls.la
check_PROGRAMS+= tests/testACLMaxUserIP
endif
DIST_SUBDIRS += auth

SUBDIRS	+= ip icmp ident log ipc mgr
DIST_SUBDIRS += ip icmp ident log ipc mgr

if ENABLE_SSL
SUBDIRS += ssl
SSL_LIBS = \
	ssl/libsslsquid.la \
	ssl/libsslutil.la
else
SSL_LOCAL_LIBS =
endif
DIST_SUBDIRS += ssl

SNMP_ALL_SOURCE = \
	SnmpRequest.h \
	snmp_core.h \
	snmp_core.cc \
	snmp_agent.h \
	snmp_agent.cc
if ENABLE_SNMP
SNMP_SOURCE = $(SNMP_ALL_SOURCE)
SUBDIRS += snmp
SNMP_LIBS = snmp/libsnmp.la $(SNMPLIB)
else
SNMP_SOURCE = 
endif
DIST_SUBDIRS += snmp

if USE_ADAPTATION
SUBDIRS += adaptation
endif
DIST_SUBDIRS += adaptation

if USE_ESI
SUBDIRS += esi
ESI_LOCAL_LIBS = \
	esi/libesi.la \
	$(top_builddir)/lib/libTrie/src/libTrie.a
ESI_LIBS = $(ESI_LOCAL_LIBS) \
	$(XMLLIB) \
	$(EXPATLIB)
else
ESI_LIBS = 
endif
DIST_SUBDIRS += esi

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
	NullDelayId.h \
	ClientDelayConfig.cc \
	ClientDelayConfig.h
	
if ENABLE_DELAY_POOLS
DELAY_POOL_SOURCE = $(DELAY_POOL_ALL_SOURCE)
else
DELAY_POOL_SOURCE = 
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
UNLINKDSOURCE = unlinkd.h unlinkd.cc
UNLINKD = unlinkd
else
UNLINKDSOURCE = unlinkd.h
UNLINKD = 
endif

WIN32_ALL_SOURCE = \
	win32.h \
	win32.cc \
	WinSvc.h \
	WinSvc.cc
if ENABLE_WIN32SPECIFIC
WIN32_SOURCE = win32.cc
WINSVC_SOURCE = WinSvc.cc
else
WIN32_SOURCE =
WINSVC_SOURCE =
endif

if USE_IPC_WIN32
IPC_SOURCE = SquidIpc.h ipc_win32.cc
else
IPC_SOURCE = SquidIpc.h ipc.cc
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
AIOPS_SOURCE = DiskIO/DiskThreads/aiops_win32.cc \
	DiskIO/DiskThreads/CommIO.cc \
	DiskIO/DiskThreads/CommIO.h
else
AIOPS_SOURCE = DiskIO/DiskThreads/aiops.cc \
	DiskIO/DiskThreads/CommIO.cc \
	DiskIO/DiskThreads/CommIO.h
endif

EXTRA_LIBRARIES = libAIO.a libBlocking.a libDiskDaemon.a libDiskThreads.a \
	libMmapped.a libIpcIo.a
noinst_LIBRARIES = $(DISK_LIBS)
noinst_LTLIBRARIES = libsquid.la

EXTRA_PROGRAMS = \
	DiskIO/DiskDaemon/diskd \
	unlinkd \
	dnsserver \
	recv-announce \
	tests/testUfs \
	tests/testCoss \
	tests/testRock \
	tests/testNull \
	ufsdump

## cfgen is used when building squid
## ufsdump is a debug utility, it is possibly useful for end users with cache
## corruption, but at this point we do not install it.
noinst_PROGRAMS = \
	cf_gen

sbin_PROGRAMS = \
	squid

bin_PROGRAMS = 


libexec_PROGRAMS = \
	$(DNSHELPER) \
	$(DISK_PROGRAMS) \
	$(UNLINKD)

cf_gen_SOURCES = cf_gen.cc
nodist_cf_gen_HEADER = cf_gen_defines.cci
## cf_gen must be stand-alone executable. It is a purely build-time executable.
cf_gen_LDADD=
cf_gen.$(OBJEXT): cf_gen_defines.cci

## cf_gen.cc needs src/cf_gen_defines.cci
INCLUDES += -I$(top_builddir)/src


ACL_REGISTRATION_SOURCES = AclRegs.cc AuthReg.cc

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

DISKIO_GEN_SOURCE = \
	DiskIO/DiskIOModules_gen.cc

DiskIO/DiskIOModules_gen.cc: Makefile
	$(SHELL) $(srcdir)/DiskIO/modules.sh $(DISK_MODULES) > DiskIO/DiskIOModules_gen.cc


# common library for all the binaries and tests. This is kindof a catch all
# and smaller libraries split from this are encouraged. Using lt convenience
# libraries, dependencies should not be a problem either.
libsquid_la_SOURCES = \
	comm.cc \
	comm.h \
	comm_err_t.h \
	CommCalls.cc \
	CommCalls.h \
	DescriptorSet.cc \
	DescriptorSet.h \
	SquidConfig.h \
	SquidConfig.cc

squid_SOURCES = \
	$(ACL_REGISTRATION_SOURCES) \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	AsyncEngine.cc \
	AsyncEngine.h \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	CacheDigest.h \
	CacheDigest.cc \
	cache_manager.cc \
	NeighborTypeDomainList.h \
	CachePeerDomainList.h \
	CachePeer.h \
	CacheManager.h \
	carp.h \
	carp.cc \
	cbdata.cc \
	cbdata.h \
	ChunkedCodingParser.cc \
	ChunkedCodingParser.h \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_reply.h \
	client_side_request.cc \
	client_side_request.h \
	ClientInfo.h \
	BodyPipe.cc \
	BodyPipe.h \
	ClientInfo.h \
	ClientRequestContext.h \
	clientStream.cc \
	clientStream.h \
	CompletionDispatcher.cc \
	CompletionDispatcher.h \
	CommRead.h \
	ConfigOption.cc \
	ConfigParser.cc \
	ConfigParser.h \
	CpuAffinity.cc \
	CpuAffinity.h \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	Debug.h \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.h \
	disk.cc \
	$(DISKIO_SOURCE) \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	enums.h \
	err_type.h \
	err_detail_type.h \
	errorpage.cc \
	errorpage.h \
	ETag.cc \
	ETag.h \
	event.cc \
	event.h \
	EventLoop.h \
	EventLoop.cc \
	external_acl.cc \
	ExternalACL.h \
	ExternalACLEntry.cc \
	ExternalACLEntry.h \
	FadingCounter.h \
	FadingCounter.cc \
	fatal.h \
	fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	fde.h \
	FileMap.h \
	filemap.cc \
	forward.cc \
	forward.h \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	Generic.h \
	globals.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	helper.h \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	hier_code.h \
	HierarchyLogEntry.h \
	$(HTCPSOURCE) \
	HttpStateFlags.h \
	http.cc \
	http.h \
	HttpStatusCode.h \
	HttpStatusLine.cc \
	HttpStatusLine.h \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrSc.h \
	HttpHdrScTarget.cc \
	HttpHdrScTarget.h \
	HttpHdrContRange.cc \
	HttpHdrContRange.h \
	HttpHeaderStat.h \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderMask.h \
	HttpHeaderRange.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpControlMsg.h \
	HttpMsg.cc \
	HttpMsg.h \
	HttpParser.cc \
	HttpParser.h \
	HttpReply.cc \
	HttpReply.h \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequest.h \
	HttpRequestMethod.cc \
	HttpRequestMethod.h \
	HttpVersion.h \
	ICP.h \
	icp_opcode.h \
	icp_v2.cc \
	icp_v3.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	ipcache.h \
	$(LEAKFINDERSOURCE) \
	SquidList.h \
	SquidList.cc \
	lookup_t.h \
	main.cc \
	Mem.h \
	mem.cc \
	mem_node.cc \
	mem_node.h \
	Mem.h \
	MemBuf.cc \
	MemObject.cc \
	MemObject.h \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Packer.h \
	Parsing.cc \
	Parsing.h \
	$(XPROF_STATS_SOURCE) \
	pconn.cc \
	pconn.h \
	PeerDigest.h \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	PeerSelectState.h \
	PingData.h \
	protos.h \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	RemovalPolicy.h \
	send-announce.h \
	send-announce.cc \
	$(SBUF_SOURCE) \
	$(SNMP_SOURCE) \
	SquidMath.h \
	SquidMath.cc \
	SquidNew.cc \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	stmem.cc \
	stmem.h \
	repl_modules.h \
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
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	StoreStats.cc \
	StoreStats.h \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	Server.cc \
	Server.h \
	swap_log_op.h \
	SwapDir.cc \
	SwapDir.h \
	MemStore.cc \
	MemStore.h \
	time.cc \
	TimeOrTag.h \
	tools.h \
	tools.cc \
	tunnel.cc \
	typedefs.h \
	$(UNLINKDSOURCE) \
	url.cc \
	URL.h \
	URLScheme.cc \
	URLScheme.h \
	urn.h \
	urn.cc \
	wccp.h \
	wccp.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	wordlist.h \
	wordlist.cc \
	$(WIN32_SOURCE) \
	$(WINSVC_SOURCE)

EXTRA_squid_SOURCES = \
	$(AIO_WIN32_ALL_SOURCES) \
	$(all_AUTHMODULES) \
	ConfigOption.h \
	$(DELAY_POOL_ALL_SOURCE) \
	dns.cc \
	dnsserver.cc \
	dns_internal.cc \
	DnsLookupDetails.cc \
	DnsLookupDetails.h \
	htcp.cc \
	htcp.h \
	ipc.cc \
	ipc_win32.cc \
	ProfStats.cc \
	LeakFinder.cc \
	LeakFinder.h \
	$(SNMP_ALL_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_ALL_SOURCE) \
	$(LOADABLE_MODULES_SOURCES)

noinst_HEADERS = \
	client_side_request.cci \
	MemBuf.cci \
	MemBuf.h \
	Store.cci \
	StoreEntryStream.h \
	String.cci \
	SquidString.h \
	SquidTime.h

BUILT_SOURCES = \
	cf_gen_defines.cci \
	cf_parser.cci \
	err_type.cc \
	err_detail_type.cc \
	globals.cc \
	hier_code.cc \
	icp_opcode.cc \
	lookup_t.cc \
	repl_modules.cc \
	swap_log_op.cc

CLEANFILES += $(BUILT_SOURCES)

nodist_squid_SOURCES = \
	$(DISKIO_GEN_SOURCE) \
	$(BUILT_SOURCES)

squid_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	$(DISK_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	anyp/libanyp.la \
	comm/libcomm.la \
	eui/libeui.la \
	icmp/libicmp.la icmp/libicmp-core.la \
	log/liblog.la \
	format/libformat.la \
	$(XTRA_OBJS) \
	$(DISK_LINKOBJS) \
	$(REPL_OBJS) \
	$(DISK_OS_LIBS) \
	$(CRYPTLIB) \
	$(REGEXLIB) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	$(SNMP_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SSLLIB) \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
squid_DEPENDENCIES = \
	$(DISK_LIBS) \
	$(DISK_LINKOBJS) \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LOCAL_LIBS) \
	$(SSL_LIBS) \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	format/libformat.la \
	ipc/libipc.la \
	mgr/libmgr.la

if USE_LOADABLE_MODULES
squid_SOURCES += $(LOADABLE_MODULES_SOURCES)
squid_LDADD += -L$(top_builddir) $(LIBLTDL)
squid_LDFLAGS = -export-dynamic -dlopen force
## when static module linking is supported and enabled:
## squid_LDFLAGS = -all-static -dlopen self
##
## LTDL headers require their local include path...
INCLUDES += $(INCLTDL)
endif

## Kerberos libraries require their include path...
INCLUDES += $(KRB5INCS)


unlinkd_SOURCES = unlinkd_daemon.cc
unlinkd_LDADD = \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

## dnsserver is a standalone helper. Do not link to any internal libraries
dnsserver_SOURCES = dnsserver.cc
dnsserver_LDADD = \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

recv_announce_SOURCES = recv-announce.cc

## What requires what..
## many things want ACLChecklist.cc
## ACLChecklist.cc wants AuthUserRequest.cc
## ACLChecklist.cc wants AuthScheme.cc
## ACLChecklist.cc wants ACLProxyAuth.cc directly
## ACLProxyAuth.cc wants ACLUserData
## ACLProxyAuth.cc wants ACLRegexData
## cache_cf.cc wants $(AUTH_LIBS)
## cache_cf.cc wants Swapdir
## cache_cf.cc wants AnyP::PortCfg
## client_side wants client_db
## client_db wants SNMP_SOURCE
## snmp_core wants ACLStringData
## SwapDir wants ConfigOption
## tools.cc wants ip/libip.la
## client_side.cc wants ip/libip.la
## mem.cc wants ClientInfo.h
## libbase.la wants cbdata.*
## libbase.la wants MemBuf.*
ufsdump_SOURCES = \
	ClientInfo.h \
	cbdata.h \
	cbdata.cc \
	debug.cc \
	int.h \
	int.cc \
	Mem.h \
	mem.cc \
	MemBuf.cc \
	MemBuf.cci \
	MemBuf.h \
	Parsing.h \
	store_key_md5.h \
	store_key_md5.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	String.cc \
	SquidNew.cc \
	time.cc \
	ufsdump.cc \
	dlink.h \
	dlink.cc \
	HelperChildConfig.h \
	tests/stub_HelperChildConfig.cc \
	HttpRequestMethod.cc \
	RemovalPolicy.cc \
	$(WIN32_SOURCE) \
	fd.h \
	tests/stub_fd.cc
ufsdump_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(XTRA_OBJS) \
	$(REPL_OBJS) \
	$(CRYPTLIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(XTRA_LIBS)
ufsdump_DEPENDENCIES = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(DISK_LIBS) \
	$(DISK_LINKOBJS) \
	$(REPL_OBJS)

nodist_ufsdump_SOURCES = \
	globals.cc

sysconf_DATA = \
	squid.conf.default \
	squid.conf.documented \
	mime.conf.default

data_DATA = \
	mib.txt

LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

include $(srcdir)/tests/Stub.list

EXTRA_DIST = \
	cf_gen_defines \
	cf.data.pre \
	cf.data.depend \
	DiskIO/modules.sh \
	mk-globals-c.pl \
	mk-globals-c.awk \
	mk-string-arrays.pl \
	mk-string-arrays.awk \
	repl_modules.sh \
	$(STUB_SOURCE) \
	mib.txt \
	mime.conf.default

libAIO_a_SOURCES = \
		$(AIO_WIN32_SOURCES) \
		DiskIO/AIO/async_io.h \
		DiskIO/AIO/AIODiskFile.cc \
		DiskIO/AIO/AIODiskFile.h \
		DiskIO/AIO/AIODiskIOStrategy.cc \
		DiskIO/AIO/AIODiskIOStrategy.h \
		DiskIO/AIO/AIODiskIOModule.cc \
		DiskIO/AIO/AIODiskIOModule.h

libBlocking_a_SOURCES = \
		DiskIO/Blocking/BlockingFile.cc \
		DiskIO/Blocking/BlockingFile.h \
		DiskIO/Blocking/BlockingIOStrategy.cc \
		DiskIO/Blocking/BlockingIOStrategy.h \
		DiskIO/Blocking/BlockingDiskIOModule.cc \
		DiskIO/Blocking/BlockingDiskIOModule.h 

libMmapped_a_SOURCES = \
		DiskIO/Mmapped/MmappedFile.cc \
		DiskIO/Mmapped/MmappedFile.h \
		DiskIO/Mmapped/MmappedIOStrategy.cc \
		DiskIO/Mmapped/MmappedIOStrategy.h \
		DiskIO/Mmapped/MmappedDiskIOModule.cc \
		DiskIO/Mmapped/MmappedDiskIOModule.h 

libIpcIo_a_SOURCES = \
		DiskIO/IpcIo/IpcIoFile.cc \
		DiskIO/IpcIo/IpcIoFile.h \
		DiskIO/IpcIo/IpcIoIOStrategy.cc \
		DiskIO/IpcIo/IpcIoIOStrategy.h \
		DiskIO/IpcIo/IpcIoDiskIOModule.cc \
		DiskIO/IpcIo/IpcIoDiskIOModule.h 

libDiskDaemon_a_SOURCES = \
		DiskIO/DiskDaemon/DiskdFile.cc \
		DiskIO/DiskDaemon/DiskdFile.h \
		DiskIO/DiskDaemon/DiskdIOStrategy.cc \
		DiskIO/DiskDaemon/DiskdIOStrategy.h \
		DiskIO/DiskDaemon/diomsg.h \
		DiskIO/DiskDaemon/DiskDaemonDiskIOModule.cc \
		DiskIO/DiskDaemon/DiskDaemonDiskIOModule.h \
		DiskIO/DiskDaemon/DiskdAction.cc \
		DiskIO/DiskDaemon/DiskdAction.h

libDiskThreads_a_SOURCES = \
		$(AIOPS_SOURCE) \
		DiskIO/DiskThreads/async_io.cc \
		DiskIO/DiskThreads/DiskThreads.h \
		DiskIO/DiskThreads/DiskThreadsDiskFile.cc \
		DiskIO/DiskThreads/DiskThreadsDiskFile.h \
		DiskIO/DiskThreads/DiskThreadsDiskIOModule.cc \
		DiskIO/DiskThreads/DiskThreadsDiskIOModule.h \
		DiskIO/DiskThreads/DiskThreadsIOStrategy.cc \
		DiskIO/DiskThreads/DiskThreadsIOStrategy.h

EXTRA_libDiskThreads_a_SOURCES = \
	DiskIO/DiskThreads/aiops.cc \
	DiskIO/DiskThreads/aiops_win32.cc \
	DiskIO/DiskThreads/CommIO.cc \
	DiskIO/DiskThreads/CommIO.h

DiskIO_DiskDaemon_diskd_SOURCES = DiskIO/DiskDaemon/diskd.cc
nodist_DiskIO_DiskDaemon_diskd_SOURCES = time.cc
DiskIO_DiskDaemon_diskd_LDADD = \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)


DEFAULT_HTTP_PORT	= 3128
DEFAULT_ICP_PORT	= 3130
DEFAULT_PREFIX		= $(prefix)
DEFAULT_CONFIG_DIR	= $(sysconfdir)
DEFAULT_CONFIG_FILE	= $(DEFAULT_CONFIG_DIR)/squid.conf
DEFAULT_MIME_TABLE	= $(DEFAULT_CONFIG_DIR)/mime.conf
DEFAULT_DNSSERVER	= $(libexecdir)/`echo dnsserver | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_SSL_CRTD	= $(libexecdir)/`echo ssl_crtd  | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_LOG_PREFIX	= $(DEFAULT_LOG_DIR)
DEFAULT_CACHE_LOG	= $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG	= $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG	= $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_NETDB_FILE	= $(DEFAULT_LOG_PREFIX)/netdb.state
DEFAULT_SSL_DB_DIR	= $(localstatedir)/lib/ssl_db
DEFAULT_PINGER		= $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_UNLINKD		= $(libexecdir)/`echo unlinkd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_LOGFILED	= $(libexecdir)/`echo log_file_daemon | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_DISKD		= $(libexecdir)/`echo diskd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_ICON_DIR	= $(datadir)/icons
DEFAULT_ERROR_DIR	= $(datadir)/errors

# Make location configure settings available to the code
DEFS += -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\" -DDEFAULT_SQUID_DATA_DIR=\"$(datadir)\" -DDEFAULT_SQUID_CONFIG_DIR=\"$(sysconfdir)\"

snmp_core.o snmp_agent.o: ../snmplib/libsnmplib.a $(top_srcdir)/include/cache_snmp.h

globals.cc: globals.h mk-globals-c.awk
	$(AWK) -f $(srcdir)/mk-globals-c.awk < $(srcdir)/globals.h > $@ || ($(RM) -f $@ && exit 1)

## Generate files containing string arrays for various enums....
hier_code.cc: hier_code.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/hier_code.h > $@ || ($(RM) -f $@ && exit 1)

err_type.cc: err_type.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/err_type.h > $@ || ($(RM) -f $@ && exit 1)

err_detail_type.cc: err_detail_type.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/err_detail_type.h | sed 's/ERR_DETAIL_//' > $@ || ($(RM) -f $@ && exit 1)

lookup_t.cc: lookup_t.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/lookup_t.h > $@ || ($(RM) -f $@ && exit 1)

icp_opcode.cc: icp_opcode.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/icp_opcode.h > $@ || ($(RM) -f $@ && exit 1)

swap_log_op.cc: swap_log_op.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/swap_log_op.h > $@ || ($(RM) -f $@ && exit 1)


## other generated files...

cache_diff: cache_diff.o debug.o globals.o store_key_md5.o
	$(CC) -o $@ $(LDFLAGS) $@.o debug.o globals.o store_key_md5.o $(STD_APP_LIBS)

test_cache_digest: test_cache_digest.o CacheDigest.o debug.o globals.o store_key_md5.o
	$(CC) -o $@ $(LDFLAGS) $@.o CacheDigest.o debug.o globals.o store_key_md5.o $(STD_APP_LIBS)

## If autodependency works well this is not needed anymore
cache_cf.o: cf_parser.cci

# cf_gen builds the configuration files.
cf_gen$(EXEEXT): $(cf_gen_SOURCES) $(cf_gen_DEPENDENCIES) cf_gen_defines.cci
	$(HOSTCXX) -o $@ $(srcdir)/cf_gen.cc -I$(srcdir) -I$(top_builddir)/include/ -I$(top_builddir)/src

# squid.conf.default is built by cf_gen when making cf_parser.cci
squid.conf.default squid.conf.documented: cf_parser.cci
	true

cf_parser.cci: cf.data cf_gen$(EXEEXT)
	./cf_gen$(EXEEXT) cf.data $(srcdir)/cf.data.depend

# The cf_gen_defines.cci is auto-generated and does not exist when the 
# dependencies computed. We need to add its include files (autoconf.h) here
cf_gen_defines.cci: $(srcdir)/cf_gen_defines $(srcdir)/cf.data.pre $(top_builddir)/include/autoconf.h
	$(AWK) -f $(srcdir)/cf_gen_defines <$(srcdir)/cf.data.pre >$@ || ($(RM) -f $@ && exit 1)


## FIXME: generate a sed command file from configure. Then this doesn't
## depend on the Makefile.
cf.data: cf.data.pre Makefile
	sed \
	-e "s%[@]DEFAULT_HTTP_PORT[@]%$(DEFAULT_HTTP_PORT)%g" \
	-e "s%[@]DEFAULT_ICP_PORT[@]%$(DEFAULT_ICP_PORT)%g" \
	-e "s%[@]DEFAULT_CACHE_EFFECTIVE_USER[@]%$(CACHE_EFFECTIVE_USER)%g" \
	-e "s%[@]DEFAULT_MIME_TABLE[@]%$(DEFAULT_MIME_TABLE)%g" \
	-e "s%[@]DEFAULT_DNSSERVER[@]%$(DEFAULT_DNSSERVER)%g" \
	-e "s%[@]DEFAULT_SSL_CRTD[@]%$(DEFAULT_SSL_CRTD)%g" \
	-e "s%[@]DEFAULT_UNLINKD[@]%$(DEFAULT_UNLINKD)%g" \
	-e "s%[@]DEFAULT_PINGER[@]%$(DEFAULT_PINGER)%g" \
	-e "s%[@]DEFAULT_DISKD[@]%$(DEFAULT_DISKD)%g" \
	-e "s%[@]DEFAULT_LOGFILED[@]%$(DEFAULT_LOGFILED)%g;" \
	-e "s%[@]DEFAULT_CACHE_LOG[@]%$(DEFAULT_CACHE_LOG)%g" \
	-e "s%[@]DEFAULT_ACCESS_LOG[@]%$(DEFAULT_ACCESS_LOG)%g" \
	-e "s%[@]DEFAULT_STORE_LOG[@]%$(DEFAULT_STORE_LOG)%g" \
	-e "s%[@]DEFAULT_PID_FILE[@]%$(DEFAULT_PID_FILE)%g" \
	-e "s%[@]DEFAULT_NETDB_FILE[@]%$(DEFAULT_NETDB_FILE)%g" \
	-e "s%[@]DEFAULT_SWAP_DIR[@]%$(DEFAULT_SWAP_DIR)%g" \
	-e "s%[@]DEFAULT_SSL_DB_DIR[@]%$(DEFAULT_SSL_DB_DIR)%g" \
	-e "s%[@]DEFAULT_ICON_DIR[@]%$(DEFAULT_ICON_DIR)%g" \
	-e "s%[@]DEFAULT_CONFIG_DIR[@]%$(DEFAULT_CONFIG_DIR)%g" \
	-e "s%[@]DEFAULT_ERROR_DIR[@]%$(DEFAULT_ERROR_DIR)%g" \
	-e "s%[@]DEFAULT_PREFIX[@]%$(DEFAULT_PREFIX)%g" \
	-e "s%[@]DEFAULT_HOSTS[@]%$(DEFAULT_HOSTS)%g" \
	-e "s%[@]SQUID[@]%SQUID\ $(VERSION)%g" \
	< $(srcdir)/cf.data.pre >$@

repl_modules.cc: repl_modules.sh Makefile
	$(SHELL) $(srcdir)/repl_modules.sh $(REPL_POLICIES) > repl_modules.cc

include $(top_srcdir)/doc/manuals/Substitute.am

squid.8: $(srcdir)/squid.8.in Makefile
	$(SUBSTITUTE) < $(srcdir)/squid.8.in > $@

man_MANS = squid.8
EXTRA_DIST += squid.8.in
CLEANFILES += squid.8

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
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_LOG_PREFIX); \
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_SWAP_DIR); \
	$(mkinstalldirs) $(DESTDIR)`dirname $(DEFAULT_PID_FILE)`

uninstall-local: squid.conf.default
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_MIME_TABLE) $(srcdir)/mime.conf.default
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_CONFIG_FILE) squid.conf.default

CLEANFILES += cf.data squid.conf.default squid.conf.documented \
	DiskIO/DiskIOModules_gen.cc \
	test_tools.cc *.a

test_tools.cc: $(top_srcdir)/test-suite/test_tools.cc
	cp $(top_srcdir)/test-suite/test_tools.cc .

# stock tools for unit tests - library independent versions of dlink_list 
# etc.
# globals.cc is needed by test_tools.cc.
# Neither of these should be disted from here.
TESTSOURCES= \
	tests/STUB.h \
	test_tools.cc \
	globals.cc

check_PROGRAMS+=\
	tests/testBoilerplate \
	tests/testCacheManager \
	tests/testDiskIO \
	tests/testEvent \
	tests/testEventLoop \
	tests/test_http_range \
	tests/testHttpParser \
	tests/testHttpReply \
	tests/testHttpRequest \
	tests/testStore \
	tests/testString \
	tests/testURL \
	tests/testConfigParser \
	tests/testStatHist \
	$(STORE_TESTS)

## NP: required to run the above list. check_PROGRAMS only builds the binaries...
TESTS += $(check_PROGRAMS)

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
#	X.cc
#nodist_tests_testX_SOURCES=\
#	$(TESTSOURCES)
#tests_testX_LDFLAGS = $(LIBADD_DL)
#tests_testX_LDADD=\
#	$(SQUID_CPPUNIT_LIBS) \
#	$(SQUID_CPPUNIT_LA) \
#	$(COMPAT_LIB) \
#tests_testX_DEPENDENCIES= $(SQUID_CPPUNIT_LA)


# - add other component .(h|cc) files needed to link and run tests
tests_testHttpReply_SOURCES=\
	cbdata.cc \
	cbdata.h \
	ETag.cc \
	fatal.h \
	tests/stub_fatal.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrContRange.h \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrSc.h \
	HttpHdrScTarget.cc \
	HttpHdrScTarget.h \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderMask.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpControlMsg.h \
	HttpMsg.cc \
	HttpMsg.h \
	HttpReply.cc \
	HttpReply.h \
	HttpStatusCode.h \
	HttpStatusLine.cc \
	HttpStatusLine.h \
	Mem.h \
	mem.cc \
	RegexList.h \
	RegexList.cc \
	MemBuf.cc \
	MemBuf.h \
	mime_header.h \
	mime_header.cc \
	Packer.cc \
	Packer.h \
	SquidString.h \
	SquidTime.h \
	String.cc \
	StrList.h \
	StrList.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_libformat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	repl_modules.h \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/stub_HttpRequest.cc \
	tests/testHttpReply.cc \
	tests/testHttpReply.h \
	tests/testMain.cc \
	time.cc \
	url.cc \
	URLScheme.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testHttpReply_SOURCES=\
	$(TESTSOURCES)
tests_testHttpReply_LDFLAGS = $(LIBADD_DL)
tests_testHttpReply_LDADD=\
	acl/libacls.la \
	acl/libapi.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	anyp/libanyp.la \
	ip/libip.la \
	base/libbase.la \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttpReply_DEPENDENCIES= $(SQUID_CPPUNIT_LA)

tests_testACLMaxUserIP_SOURCES= \
	cbdata.cc \
	ClientInfo.h \
	ConfigOption.cc \
	ConfigParser.cc \
	DiskIO/ReadRequest.cc \
	DiskIO/WriteRequest.cc \
	ETag.cc \
	event.cc \
	fatal.h \
	tests/stub_fatal.cc \
	FileMap.h \
	filemap.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	HttpBody.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpRequestMethod.cc \
	int.h \
	int.cc \
	SquidList.h \
	SquidList.cc \
	mem_node.cc \
	Packer.cc \
	Parsing.cc \
	SquidMath.cc \
	StatCounters.cc \
	StatCounters.h \
	StatHist.h \
	StrList.h \
	StrList.cc \
	tests/stub_StatHist.cc \
	stmem.cc \
	String.cc \
	store_dir.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	store_key_md5.h \
	store_key_md5.cc \
	swap_log_op.cc \
	swap_log_op.h \
	SwapDir.cc \
	SwapDir.h \
	log/access_log.h \
	tests/stub_access_log.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_debug.cc \
	tests/stub_DelayId.cc \
	tests/stub_DiskIOModule.cc \
	tests/stub_errorpage.cc \
	fd.h \
	tests/stub_fd.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_HttpReply.cc \
	tests/stub_ipc_TypedMsgHdr.cc \
	tests/stub_libcomm.cc \
	tests/stub_libformat.cc \
	tests/stub_libsslsquid.cc \
	tests/stub_MemObject.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_pconn.cc \
	tests/stub_Port.cc \
	repl_modules.h \
	tests/stub_store.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_stats.cc \
	tests/stub_store_swapout.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/stub_cache_manager.cc \
	tests/stub_UdsOp.cc \
	tests/testACLMaxUserIP.cc \
	tests/testACLMaxUserIP.h \
	tests/testMain.cc \
	time.cc \
	url.cc \
	URL.h \
	URLScheme.cc \
	URLScheme.h \
	Mem.h \
	mem.cc \
	MemBuf.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testACLMaxUserIP_SOURCES= \
	$(TESTSOURCES)
tests_testACLMaxUserIP_LDADD= \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	anyp/libanyp.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(DISK_OS_LIBS) \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testACLMaxUserIP_LDFLAGS = $(LIBADD_DL)
##tests_testACLMaxUserIP_DEPENDENCIES = \
##	$(SQUID_CPPUNIT_LA)

## a demonstration test that does nothing but shows the salient points
## involved in writing tests.
tests_testBoilerplate_SOURCES = \
	tests/testBoilerplate.cc \
	tests/testMain.cc \
	tests/testBoilerplate.h \
	time.cc
nodist_tests_testBoilerplate_SOURCES = \
	$(TESTSOURCES)
tests_testBoilerplate_LDADD= \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testBoilerplate_LDFLAGS = $(LIBADD_DL)
tests_testBoilerplate_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

## Tests of the CacheManager module.
tests_testCacheManager_SOURCES = \
	AccessLogEntry.cc \
	$(ACL_REGISTRATION_SOURCES) \
	debug.cc \
	HttpParser.cc \
	HttpParser.h \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	Mem.h \
	mem.cc \
	String.cc \
	tests/testCacheManager.cc \
	tests/testCacheManager.h \
	tests/testMain.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	time.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	CacheDigest.h \
	CacheDigest.cc \
	carp.h \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	$(DELAY_POOL_SOURCE) \
	$(DISKIO_SOURCE) \
	disk.h \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	ETag.cc \
	event.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	FileMap.h \
	filemap.cc \
	forward.cc \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	gopher.h \
	gopher.cc \
	hier_code.h \
	helper.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	$(HTCPSOURCE) \
	HttpStateFlags.h \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	SquidList.h \
	SquidList.cc \
	multicast.h \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	SquidMath.h \
	SquidMath.cc \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StrList.h \
	StrList.cc \
	tests/stub_StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	tools.h \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	MemStore.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	URLScheme.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	FadingCounter.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testCacheManager_SOURCES = \
	$(BUILT_SOURCES) \
	$(DISKIO_GEN_SOURCE)
# comm.cc only requires comm/libcomm.la until fdc_table is dead.
tests_testCacheManager_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	comm/libcomm.la \
	icmp/libicmp.la icmp/libicmp-core.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	anyp/libanyp.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testCacheManager_LDFLAGS = $(LIBADD_DL)
tests_testCacheManager_DEPENDENCIES = \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_testDiskIO_SOURCES = \
	CacheDigest.h \
	CacheDigest.cc \
	cbdata.cc \
	client_db.h \
	ClientInfo.h \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	$(DISKIO_SOURCE) \
	disk.h \
	disk.cc \
	ETag.cc \
	EventLoop.cc \
	event.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.h \
	fde.cc \
	FileMap.h \
	filemap.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHdrRange.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	int.h \
	int.cc \
	SquidList.h \
	SquidList.cc \
	MemBuf.cc \
	MemObject.cc \
	mem_node.cc \
	Mem.h \
	mem.cc \
	Packer.cc \
	Parsing.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	RequestFlags.h \
	RequestFlags.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	stmem.cc \
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
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_swapout.cc \
	store_swapmeta.cc \
	repl_modules.h \
	store.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	SwapDir.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_client_db.cc \
	client_side_request.h \
	tests/stub_client_side_request.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	tests/stub_helper.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_http.cc \
	tests/stub_icp.cc \
	internal.h \
	tests/stub_internal.cc \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_pconn.cc \
	tests/stub_Port.cc \
	tests/stub_store_client.cc \
	tests/stub_store_stats.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_UdsOp.cc \
	tests/testDiskIO.cc \
	tests/testDiskIO.h \
	tests/testMain.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	time.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	URLScheme.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc \
	tools.h \
	tests/stub_tools.cc
nodist_tests_testDiskIO_SOURCES= \
	$(TESTSOURCES) \
	$(DISKIO_GEN_SOURCE) \
	SquidMath.cc \
	SquidMath.h \
	swap_log_op.cc
tests_testDiskIO_LDADD = \
	SquidConfig.o \
	CommCalls.o \
	DnsLookupDetails.o \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	libsquid.la \
	comm/libcomm.la \
	anyp/libanyp.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	acl/libapi.la \
	mgr/libmgr.la \
	ipc/libipc.la \
	base/libbase.la \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testDiskIO_LDFLAGS = $(LIBADD_DL)
tests_testDiskIO_DEPENDENCIES = \
	$(DISK_LIBS) \
	$(SWAP_TEST_DS) \
	$(SQUID_CPPUNIT_LA)

## Tests of the Even module.
tests_testEvent_SOURCES = \
	AccessLogEntry.cc \
	$(ACL_REGISTRATION_SOURCES) \
	BodyPipe.cc \
	CacheDigest.h \
	CacheDigest.cc \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	cache_manager.cc \
	carp.h \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	$(DISKIO_SOURCE) \
	disk.h \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	ETag.cc \
	event.cc \
	EventLoop.h \
	EventLoop.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	FileMap.h \
	filemap.cc \
	forward.cc \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	gopher.h \
	gopher.cc \
	helper.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpParser.cc \
	HttpParser.h \
	HttpReply.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	SquidList.h \
	SquidList.cc \
	Mem.h \
	mem.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	StrList.h \
	StrList.cc \
	$(SNMP_SOURCE) \
	SquidMath.cc \
	SquidMath.h \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	tests/CapturingStoreEntry.h \
	tests/testEvent.cc \
	tests/testEvent.h \
	tests/testMain.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tools.h \
	tools.cc \
	tunnel.cc \
	MemStore.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	URLScheme.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testEvent_SOURCES = \
	$(BUILT_SOURCES) \
	$(DISKIO_GEN_SOURCE)
tests_testEvent_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	anyp/libanyp.la \
	icmp/libicmp.la icmp/libicmp-core.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEvent_LDFLAGS = $(LIBADD_DL)
tests_testEvent_DEPENDENCIES = \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

## Tests of the EventLoop module.
tests_testEventLoop_SOURCES = \
	AccessLogEntry.cc \
	$(ACL_REGISTRATION_SOURCES) \
	BodyPipe.cc \
	CacheDigest.h \
	CacheDigest.cc \
	cache_manager.cc \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	carp.h \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	$(DISKIO_SOURCE) \
	disk.h \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	ETag.cc \
	EventLoop.h \
	EventLoop.cc \
	event.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	FileMap.h \
	filemap.cc \
	forward.cc \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	gopher.h \
	gopher.cc \
	helper.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpParser.cc \
	HttpParser.h \
	HttpReply.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	SquidList.h \
	SquidList.cc \
	MemBuf.cc \
	MemObject.cc \
	Mem.h \
	mem.cc \
	mem_node.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	RemovalPolicy.cc \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	SquidMath.h \
	SquidMath.cc \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	Mem.h \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	StrList.h \
	StrList.cc \
	SwapDir.cc \
	tests/testEventLoop.cc \
	tests/testEventLoop.h \
	tests/testMain.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tools.h \
	tools.cc \
	tunnel.cc \
	MemStore.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	URLScheme.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testEventLoop_SOURCES = \
	$(BUILT_SOURCES) \
	$(DISKIO_GEN_SOURCE)
tests_testEventLoop_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	anyp/libanyp.la \
	icmp/libicmp.la icmp/libicmp-core.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEventLoop_LDFLAGS = $(LIBADD_DL)
tests_testEventLoop_DEPENDENCIES = \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_test_http_range_SOURCES = \
	AccessLogEntry.cc \
	$(ACL_REGISTRATION_SOURCES) \
	BodyPipe.cc \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	cache_manager.cc \
	CacheDigest.h \
	CacheDigest.cc \
	carp.h \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	$(DISKIO_SOURCE) \
	disk.h \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	ETag.cc \
	event.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	FileMap.h \
	filemap.cc \
	forward.cc \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	gopher.h \
	gopher.cc \
	helper.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpMsg.cc \
	HttpParser.cc \
	HttpParser.h \
	HttpReply.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	SquidList.h \
	SquidList.cc \
	MemBuf.cc \
	MemObject.cc \
	Mem.h \
	mem.cc \
	mem_node.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Parsing.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	pconn.cc \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	SquidMath.h \
	SquidMath.cc \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_io.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	StrList.h \
	StrList.cc \
	SwapDir.cc \
	tests/test_http_range.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_main_cc.cc \
	tests/stub_MemStore.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tools.h \
	tools.cc \
	tunnel.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	URLScheme.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_test_http_range_SOURCES = \
	$(BUILT_SOURCES) \
	$(DISKIO_GEN_SOURCE)
tests_test_http_range_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	anyp/libanyp.la \
	icmp/libicmp.la icmp/libicmp-core.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	ipc/libipc.la \
	base/libbase.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_test_http_range_LDFLAGS = $(LIBADD_DL)
tests_test_http_range_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

tests_testHttpParser_SOURCES = \
	Debug.h \
	HttpParser.cc \
	HttpParser.h \
	MemBuf.cc \
	MemBuf.h \
	Mem.h \
	mem.cc \
	String.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_debug.cc \
	tests/stub_event.cc \
	tests/stub_HelperChildConfig.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/testHttpParser.cc \
	tests/testHttpParser.h \
	tests/testMain.cc \
	time.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testHttpParser_SOURCES = \
	$(TESTSOURCES)
tests_testHttpParser_LDADD= \
	SquidConfig.o \
	base/libbase.la \
	ip/libip.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttpParser_LDFLAGS = $(LIBADD_DL)
tests_testHttpParser_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

## Tests of the HttpRequest module.
tests_testHttpRequest_SOURCES = \
	AccessLogEntry.cc \
	$(ACL_REGISTRATION_SOURCES) \
	HttpParser.cc \
	HttpParser.h \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	Mem.h \
	mem.cc \
	String.cc \
	tests/testHttpRequest.h \
	tests/testHttpRequest.cc \
	tests/testHttpRequestMethod.h \
	tests/testHttpRequestMethod.cc \
	tests/testMain.cc \
	tests/stub_DiskIOModule.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	time.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	debug.cc \
	CacheDigest.h \
	CacheDigest.cc \
	carp.h \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	$(DELAY_POOL_SOURCE) \
	disk.h \
	disk.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	forward.cc \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	gopher.h \
	gopher.cc \
	helper.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	SquidList.h \
	SquidList.cc \
	multicast.h \
	multicast.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	SquidMath.h \
	SquidMath.cc \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	StrList.h \
	StrList.cc \
	event.cc \
	tools.h \
	tools.cc \
	tunnel.cc \
	SwapDir.cc \
	MemStore.cc \
	url.cc \
	URLScheme.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	FadingCounter.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testHttpRequest_SOURCES = \
	$(BUILT_SOURCES)
tests_testHttpRequest_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	base/libbase.la \
	mgr/libmgr.la \
	anyp/libanyp.la \
	$(SNMP_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(DISK_OS_LIBS) \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttpRequest_LDFLAGS = $(LIBADD_DL)
tests_testHttpRequest_DEPENDENCIES = \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

## why so many sources? well httpHeaderTools requites ACLChecklist & friends.
## first line - what we are testing.
tests_testStore_SOURCES= \
	CacheDigest.h \
	CacheDigest.cc \
	cbdata.cc \
	ClientInfo.h \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	disk.h \
	disk.cc \
	DiskIO/ReadRequest.cc \
	DiskIO/WriteRequest.cc \
	ETag.cc \
	event.cc \
	EventLoop.cc \
	fatal.h \
	tests/stub_fatal.cc \
	FileMap.h \
	filemap.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpMsg.cc \
	HttpRequestMethod.cc \
	RequestFlags.cc \
	RequestFlags.h \
	int.h \
	int.cc \
	SquidList.h \
	SquidList.cc \
	Mem.h \
	mem.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	Packer.cc \
	Parsing.cc \
	RemovalPolicy.cc \
	refresh.h \
	refresh.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_dir.cc \
	store_io.cc \
	store_swapout.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaUnpacker.cc \
	StoreMetaURL.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	store_key_md5.h \
	store_key_md5.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	SwapDir.cc \
	tests/CapturingStoreEntry.h \
	log/access_log.h \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_client_side_request.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_DiskIOModule.cc \
	tests/stub_errorpage.cc \
	fd.h \
	fde.h \
	tests/stub_fd.cc \
	tests/stub_helper.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_http.cc \
	tests/stub_libformat.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpReply.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_libcomm.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_Port.cc \
	tests/stub_store_client.cc \
	tests/stub_store_stats.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_swapout.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/stub_UdsOp.cc \
	tests/testMain.cc \
	tests/testStore.cc \
	tests/testStore.h \
	tests/testStoreEntryStream.cc \
	tests/testStoreEntryStream.h \
	tests/testStoreController.cc \
	tests/testStoreController.h \
	tests/testStoreHashIndex.cc \
	tests/testStoreHashIndex.h \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	tests/TestSwapDir.cc \
	tests/TestSwapDir.h \
	time.cc \
	url.cc \
	URLScheme.cc \
	wordlist.h \
	wordlist.cc

nodist_tests_testStore_SOURCES= \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
	swap_log_op.cc

tests_testStore_LDADD= \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	mgr/libmgr.la \
	ipc/libipc.la \
	anyp/libanyp.la \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	CommCalls.o \
	DnsLookupDetails.o \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testStore_LDFLAGS = $(LIBADD_DL)
tests_testStore_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

## string needs mem.cc.
## mem.cc needs ClientInfo.h
## libsquid pulls in SquidConfig and children. stub them.
tests_testString_SOURCES = \
	ClientInfo.h \
	Mem.h \
	mem.cc \
	MemBuf.cc \
	String.cc \
	tests/testMain.cc \
	tests/testString.cc \
	tests/testString.h \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_debug.cc \
	tests/stub_HelperChildConfig.cc \
	tools.h \
	tests/stub_tools.cc \
	time.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testString_SOURCES = \
	$(TESTSOURCES)
tests_testString_LDADD = \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testString_LDFLAGS = $(LIBADD_DL)
tests_testString_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

SWAP_TEST_DS =\
	repl_modules.o \
	$(DISK_LIBS) \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_testUfs_SOURCES = \
	tests/testUfs.cc \
	tests/testMain.cc \
	tests/testUfs.h \
	tests/stub_cache_manager.cc \
	tests/stub_client_db.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_icp.cc \
	tests/stub_ipc.cc \
	tests/stub_MemStore.cc \
	tests/stub_pconn.cc \
	tests/stub_Port.cc \
	tests/stub_UdsOp.cc \
	internal.h \
	tests/stub_internal.cc \
	tests/stub_libformat.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_stats.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.h \
	fde.cc \
	client_db.h \
	disk.h \
	disk.cc \
	FileMap.h \
	filemap.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	int.h \
	int.cc \
	RequestFlags.h \
	RequestFlags.cc \
	SquidList.h \
	SquidList.cc \
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
	event.cc \
	$(DELAY_POOL_SOURCE) \
	CacheDigest.h \
	CacheDigest.cc \
	ConfigParser.cc \
	EventLoop.cc \
	HttpMsg.cc \
	RemovalPolicy.cc \
	store_dir.cc \
	repl_modules.h \
	store.cc \
	HttpRequestMethod.cc \
	store_key_md5.h \
	store_key_md5.cc \
	Parsing.cc \
	ConfigOption.cc \
	SwapDir.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_helper.cc \
	cbdata.cc \
	String.cc \
	tests/stub_debug.cc \
	tests/stub_client_side_request.cc \
	tests/stub_http.cc \
	mem_node.cc \
	stmem.cc \
	mime.h \
	tests/stub_mime.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeader.h \
	HttpHeader.cc \
	Mem.h \
	mem.cc \
	ClientInfo.h \
	MemBuf.cc \
	HttpHdrContRange.cc \
	Packer.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	url.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	StatHist.cc \
	StrList.h \
	StrList.cc \
	HttpHdrRange.cc \
	ETag.cc \
	tests/stub_errorpage.cc \
	tests/stub_HttpRequest.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	refresh.h \
	refresh.cc \
	tests/stub_store_client.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	time.cc \
	URLScheme.cc \
	wordlist.h \
	wordlist.cc \
	$(DISKIO_SOURCE)

nodist_tests_testUfs_SOURCES = \
	$(TESTSOURCES) \
	$(DISKIO_GEN_SOURCE) \
	SquidMath.cc \
	SquidMath.h \
	swap_log_op.cc
tests_testUfs_LDADD = \
	CommCalls.o \
	DnsLookupDetails.o \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	mgr/libmgr.la \
	$(REPL_OBJS) \
	acl/libacls.la \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	acl/libapi.la \
	ipc/libipc.la \
	$(SSL_LIBS) \
	comm/libcomm.la \
	anyp/libanyp.la \
	base/libbase.la \
	ip/libip.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testUfs_LDFLAGS = $(LIBADD_DL)
tests_testUfs_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testRock_SOURCES = \
	cbdata.cc \
	CacheDigest.h \
	CacheDigest.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	disk.h \
	disk.cc \
	ETag.cc \
	EventLoop.cc \
	event.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.h \
	fde.cc \
	FileMap.h \
	filemap.cc \
	HttpHeaderFieldStat.h \
	HttpBody.h \
	HttpBody.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	int.h \
	int.cc \
	SquidList.h \
	SquidList.cc \
	Mem.h \
	mem.cc \
	MemBuf.cc \
	MemObject.cc \
	mem_node.cc \
	Packer.cc \
	Parsing.cc \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMeta.cc \
	StoreMetaMD5.cc \
	StoreMetaSTD.cc \
	StoreMetaSTDLFS.cc \
	StoreMetaURL.cc \
	StoreMetaUnpacker.cc \
	StoreMetaVary.cc \
	StoreSwapLogData.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	SwapDir.cc \
	tests/testRock.cc \
	tests/testMain.cc \
	tests/testRock.h \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	log/access_log.h \
	tests/stub_access_log.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	client_db.h \
	tests/stub_client_db.cc \
	tests/stub_client_side_request.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_http.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_icp.cc \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_Port.cc \
	tests/stub_pconn.cc \
	tests/stub_store_client.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_stats.cc \
	tools.h \
	tests/stub_tools.cc \
	time.cc \
	url.cc \
	URLScheme.cc \
	wordlist.h \
	wordlist.cc \
	$(DELAY_POOL_SOURCE) \
	$(DISKIO_SOURCE) \
	$(UNLINKDSOURCE)
nodist_tests_testRock_SOURCES = \
	$(DISKIO_GEN_SOURCE) \
	swap_log_op.cc \
	SquidMath.cc \
	SquidMath.h \
	$(TESTSOURCES)
tests_testRock_LDADD = \
	libsquid.la \
	comm/libcomm.la \
	anyp/libanyp.la \
	ip/libip.la \
	fs/libfs.la \
	$(AUTH_LIBS) \
	$(COMMON_LIBS) \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	acl/libacls.la \
	acl/libapi.la \
	acl/libstate.la \
	eui/libeui.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	base/libbase.la \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testRock_LDFLAGS = $(INCLUDES) $(LIBADD_DL)
tests_testRock_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testCoss_SOURCES = \
	tests/testCoss.cc \
	tests/testMain.cc \
	tests/testCoss.h \
	tests/stub_cache_manager.cc \
	client_db.h \
	tests/stub_client_db.cc \
	tests/stub_debug.cc \
	tests/stub_HelperChildConfig.cc \
	internal.h \
	tests/stub_internal.cc \
	tests/stub_ipc.cc \
	tests/stub_pconn.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_stats.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.h \
	fde.cc \
	disk.h \
	disk.cc \
	FileMap.h \
	filemap.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	int.h \
	int.cc \
	SquidList.h \
	SquidList.cc \
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
	event.cc \
	$(DELAY_POOL_SOURCE) \
	CacheDigest.h \
	CacheDigest.cc \
	ConfigParser.cc \
	EventLoop.cc \
	HttpMsg.cc \
	RemovalPolicy.cc \
	store_dir.cc \
	repl_modules.h \
	store.cc \
	HttpRequestMethod.cc \
	store_key_md5.h \
	store_key_md5.cc \
	Parsing.cc \
	ConfigOption.cc \
	SwapDir.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_helper.cc \
	cbdata.cc \
	String.cc \
	tests/stub_client_side_request.cc \
	tests/stub_http.cc \
	mem_node.cc \
	stmem.cc \
	mime.h \
	tests/stub_mime.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeader.h \
	HttpHeader.cc \
	Mem.h \
	mem.cc \
	ClientInfo.h \
	MemBuf.cc \
	HttpHdrContRange.cc \
	Packer.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	url.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	tests/stub_errorpage.cc \
	tests/stub_HttpRequest.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	refresh.h \
	refresh.cc \
	tests/stub_MemStore.cc \
	tests/stub_Port.cc \
	tests/stub_store_client.cc \
	tests/stub_store_stats.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/stub_UdsOp.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	time.cc \
	URLScheme.cc \
	wordlist.h \
	wordlist.cc \
	$(DISKIO_SOURCE)

nodist_tests_testCoss_SOURCES = \
	swap_log_op.cc \
	SquidMath.cc \
	SquidMath.h \
	$(TESTSOURCES) \
	$(DISKIO_GEN_SOURCE)
tests_testCoss_LDADD = \
	anyp/libanyp.la \
	libsquid.la \
	$(REGEXLIB) \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	libsquid.la \
	comm/libcomm.la \
	ip/libip.la \
	fs/libfs.la \
	mgr/libmgr.la \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	$(COMMON_LIBS) \
	$(SSL_LIBS) \
	acl/libapi.la \
	ipc/libipc.la \
	base/libbase.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testCoss_LDFLAGS = $(LIBADD_DL)
tests_testCoss_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testNull_SOURCES = \
	tests/testNull.cc \
	tests/testMain.cc \
	tests/testNull.h \
	internal.h \
	tests/stub_internal.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_stats.cc \
	fd.h \
	fd.cc \
	disk.h \
	disk.cc \
	FileMap.h \
	filemap.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpReply.cc \
	HttpStatusLine.cc \
	int.h \
	int.cc \
	SquidList.h \
	SquidList.cc \
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
	event.cc \
	$(DELAY_POOL_SOURCE) \
	CacheDigest.h \
	CacheDigest.cc \
	ConfigParser.cc \
	EventLoop.cc \
	HttpMsg.cc \
	RemovalPolicy.cc \
	store_dir.cc \
	repl_modules.h \
	store.cc \
	HttpRequestMethod.cc \
	store_key_md5.h \
	store_key_md5.cc \
	Parsing.cc \
	ConfigOption.cc \
	SwapDir.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_helper.cc \
	cbdata.cc \
	String.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_client_side_request.cc \
	tests/stub_http.cc \
	mem_node.cc \
	stmem.cc \
	mime.h \
	tests/stub_mime.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeader.h \
	HttpHeader.cc \
	Mem.h \
	mem.cc \
	ClientInfo.h \
	MemBuf.cc \
	HttpHdrContRange.cc \
	Packer.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	url.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	tests/stub_errorpage.cc \
	tests/stub_HttpRequest.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	refresh.h \
	refresh.cc \
	tests/stub_store_client.cc \
	tests/stub_store_stats.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	time.cc \
	URLScheme.cc \
	wordlist.h \
	wordlist.cc \
	$(DISKIO_SOURCE)

nodist_tests_testNull_SOURCES = \
	$(TESTSOURCES) \
	$(DISKIO_GEN_SOURCE)
tests_testNull_LDADD = \
	$(REGEXLIB) \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	acl/libapi.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testNull_LDFLAGS = $(LIBADD_DL)
tests_testNull_DEPENDENCIES = \
	$(SWAP_TEST_DS)

## Tests of the URL module.
## TODO: Trim this down once the insanity is over.
tests_testURL_SOURCES = \
	AccessLogEntry.cc \
	$(ACL_REGISTRATION_SOURCES) \
	BodyPipe.cc \
	cache_cf.h \
	AuthReg.h \
	YesNoNone.h \
	YesNoNone.cc \
	RefreshPattern.h \
	cache_cf.cc \
	cache_manager.cc \
	CacheDigest.h \
	CacheDigest.cc \
	carp.h \
	carp.cc \
	cbdata.cc \
	ChunkedCodingParser.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	$(DELAY_POOL_SOURCE) \
	disk.h \
	disk.cc \
	DiskIO/ReadRequest.cc \
	DiskIO/WriteRequest.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	ETag.cc \
	event.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	FileMap.h \
	filemap.cc \
	forward.cc \
	fqdncache.h \
	fqdncache.cc \
	ftp.h \
	ftp.cc \
	gopher.h \
	gopher.cc \
	helper.cc \
	HelperChildConfig.h \
	HelperChildConfig.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpHeaderFieldStat.h \
	HttpHdrCc.h \
	HttpHdrCc.cc \
	HttpHdrCc.cci \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpMsg.cc \
	HttpParser.cc \
	HttpParser.h \
	HttpReply.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	HttpStatusLine.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	SquidList.h \
	SquidList.cc \
	multicast.h \
	multicast.cc \
	Mem.h \
	mem.cc \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	neighbors.h \
	neighbors.cc \
	Packer.cc \
	Parsing.cc \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	Server.cc \
	$(SNMP_SOURCE) \
	SquidMath.h \
	SquidMath.cc \
	IoStats.h \
	stat.h \
	stat.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	store_digest.cc \
	store_dir.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_log.h \
	store_log.cc \
	store_rebuild.h \
	store_rebuild.cc \
	store_swapin.h \
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
	StrList.h \
	StrList.cc \
	SwapDir.cc \
	MemStore.cc \
	tests/stub_debug.cc \
	tests/stub_DiskIOModule.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	tests/testURL.cc \
	tests/testURL.h \
	tests/testURLScheme.cc \
	tests/testURLScheme.h \
	tests/testMain.cc \
	time.cc \
	tools.h \
	tools.cc \
	tunnel.cc \
	url.cc \
	URLScheme.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	wccp2.cc \
	whois.h \
	whois.cc \
	FadingCounter.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testURL_SOURCES = \
	$(BUILT_SOURCES)
tests_testURL_LDADD = \
	anyp/libanyp.la \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	comm/libcomm.la \
	log/liblog.la \
	$(DISK_OS_LIBS) \
	format/libformat.la \
	$(REGEXLIB) \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testURL_LDFLAGS = $(LIBADD_DL)
tests_testURL_DEPENDENCIES = \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_testConfigParser_SOURCES = \
	ClientInfo.h \
	Mem.h \
	mem.cc \
	MemBuf.cc \
	String.cc \
	ConfigParser.cc \
	fatal.h \
	tests/stub_fatal.cc \
	tests/testMain.cc \
	tests/testConfigParser.cc \
	tests/testConfigParser.h \
	cache_cf.h \
	YesNoNone.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_debug.cc \
	tests/stub_HelperChildConfig.cc \
	tools.h \
	tests/stub_tools.cc \
	time.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testConfigParser_SOURCES = \
	$(TESTSOURCES)
tests_testConfigParser_LDADD = \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testConfigParser_LDFLAGS = $(LIBADD_DL)
tests_testConfigParser_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)
	
tests_testStatHist_SOURCES = \
	cbdata.cc \
	fatal.h \
	tests/stub_fatal.cc \
	MemBuf.cc \
	StatHist.cc \
	StatHist.h \
	String.cc \
	tests/stub_cache_manager.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_DelayId.cc \
	tests/stub_HelperChildConfig.cc \
	Mem.h \
	tests/stub_mem.cc \
	tests/stub_MemObject.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_pconn.cc \
	tests/stub_stmem.cc \
	repl_modules.h \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/testMain.cc \
	tests/testStatHist.cc \
	tests/testStatHist.h \
	time.cc
nodist_tests_testStatHist_SOURCES = \
	$(TESTSOURCES)
tests_testStatHist_LDFLAGS = $(LIBADD_DL)
tests_testStatHist_LDADD = \
	base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(COMPAT_LIB)
tests_testStatHist_DEPENDENCIES = $(SQUID_CPPUNIT_LA)


TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/*.h $(srcdir)/DiskIO/*.h $(srcdir)/DiskIO/*/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1
## src/repl/ has no .h files and its own makefile.

CLEANFILES += testHeaders
.PHONY: testHeaders

