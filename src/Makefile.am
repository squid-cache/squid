#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.99 2004/12/20 18:01:06 robertc Exp $
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

if USE_SNMP
SNMPSOURCE = snmp_core.cc snmp_agent.cc
else
SNMPSOURCE = 
endif

TESTS=$(check_PROGRAMS)
check_PROGRAMS=

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
LEAKFINDERSOURCE =  leakfinder.cc
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

SSL_ALL_SOURCE = \
	ACLCertificateData.cc \
	ACLCertificateData.h  \
	ACLCertificate.cc \
	ACLCertificate.h  \
	ssl_support.cc \
	ssl_support.h
if ENABLE_SSL
SSL_SOURCE = $(SSL_ALL_SOURCE)
else
SSL_SOURCE = 
endif

if ENABLE_WIN32SPECIFIC
WIN32SOURCE = win32.cc
else
WIN32SOURCE = 
endif

IDENT_ALL_SOURCE = ACLIdent.cc ACLIdent.h ident.cc
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

EPOLL_ALL_SOURCE = comm_epoll.cc
if USE_EPOLL
EPOLL_SOURCE = $(EPOLL_ALL_SOURCE)
else
EPOLL_SOURCE = 
endif

AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@

SUBDIRS		= fs repl auth

EXTRA_LIBRARIES = libAIO.a libBlocking.a libDiskDaemon.a libDiskThreads.a
noinst_LIBRARIES = @DISK_LIBS@

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/lib/libTrie/include

EXTRA_PROGRAMS = \
	DiskIO/DiskDaemon/diskd \
	unlinkd \
	pinger \
	dnsserver \
	recv-announce \
	ufsdump 

noinst_PROGRAMS = \
	cf_gen

sbin_PROGRAMS = \
	squid

bin_PROGRAMS = \
	squidclient


libexec_PROGRAMS = \
	$(PINGER) \
	$(DNSSERVER) \
	@DISK_PROGRAMS@ \
	$(UNLINKD) \
	cachemgr$(CGIEXT)

cf_gen_SOURCES = cf_gen.cc defines.h
nodist_cf_gen_HEADER = cf_gen_defines.h
cf_gen.$(OBJEXT): cf_gen_defines.h
squidclient_SOURCES = client.cc
cachemgr__CGIEXT__SOURCES = cachemgr.cc

all_FSMODULES = \
	fs/aufs/StoreFSaufs.cc \
	fs/coss/StoreFScoss.cc \
	fs/diskd/StoreFSdiskd.cc \
	fs/null/StoreFSnull.cc \
	fs/ufs/StoreFSufs.cc

all_DISKIOMODULES = \
	DiskIO/AIO/AIODiskIOModule.cc \
	DiskIO/Blocking/BlockingDiskIOModule.cc \
	DiskIO/DiskDaemon/DiskDaemonDiskIOModule.cc \
	DiskIO/DiskThreads/DiskThreadsDiskIOModule.cc

all_AUTHMODULES = \
	auth/basic/basicScheme.cc \
	auth/basic/basicScheme.h \
	auth/digest/digestScheme.cc \
	auth/digest/digestScheme.h \
	auth/ntlm/ntlmScheme.cc \
	auth/ntlm/ntlmScheme.h 

EXTRA_squid_SOURCES = \
	$(all_FSMODULES) \
	$(all_DISKIOMODULES) \
	$(all_AUTHMODULES) \
	$(ARP_ACL_ALL_SOURCE) \
	ConfigOption.h \
	$(DELAY_POOL_ALL_SOURCE) \
	dns.cc \
	dnsserver.cc \
	dns_internal.cc \
	$(EPOLL_ALL_SOURCE) \
	htcp.cc \
	htcp.h \
	$(IDENT_ALL_SOURCE) \
	$(ESI_ALL_SOURCE) \
	ProfStats.cc \
	leakfinder.cc \
	snmp_core.cc \
	snmp_agent.cc \
	unlinkd.cc \
	$(SSL_ALL_SOURCE) \
	win32.cc

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

squid_SOURCES = \
	access_log.cc \
	AccessLogEntry.h \
	acl.cc \
	ACL.h \
	ACLChecklist.cc \
	ACLChecklist.h \
	$(squid_ACLSOURCES) \
	asn.cc \
	authenticate.cc \
	authenticate.h \
	AuthConfig.cc \
	AuthConfig.h \
	AuthScheme.cc \
	AuthScheme.h \
	AuthUser.cc \
	AuthUserRequest.cc \
	cache_cf.cc \
	CacheDigest.cc \
	cache_manager.cc \
	carp.cc \
	cbdata.cc \
	client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_reply.h \
	client_side_request.cc \
	client_side_request.h \
	clientStream.cc \
	clientStream.h \
	comm.cc \
	comm.h \
	comm_select.cc \
	comm_poll.cc \
	comm_kqueue.cc \
	CommRead.h \
	ConfigOption.cc \
	ConfigParser.h \
	ConnectionDetail.h \
	debug.cc \
	Debug.h \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	DiskIO/DiskIOModule.cc \
	DiskIO/ReadRequest.cc \
	DiskIO/ReadRequest.h \
	DiskIO/WriteRequest.cc \
	DiskIO/WriteRequest.h \
	$(DNSSOURCE) \
	$(EPOLL_SOURCE) \
	enums.h \
	errorpage.cc \
	$(ESI_SOURCE) \
	ETag.cc \
	event.cc \
	external_acl.cc \
	ExternalACL.h \
	ExternalACLEntry.cc \
	ExternalACLEntry.h \
	fd.cc \
	fde.cc \
	fde.h \
	filemap.cc \
	forward.cc \
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
	HttpHdrScTarget.cc \
	HttpHdrContRange.cc \
	HttpHdrContRange.h \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderRange.h \
	HttpHeaderTools.cc \
	HttpBody.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpReply.h \
	HttpRequest.cc \
	HttpRequest.h \
	HttpVersion.h \
	icmp.cc \
	ICP.h \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	int.cc \
	internal.cc \
	ipc.cc \
	ipcache.cc \
	IPInterception.cc \
	IPInterception.h \
	$(LEAKFINDERSOURCE) \
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
	$(XPROF_STATS_SOURCE) \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	PeerSelectState.h \
	PingData.h \
	protos.h \
	redirect.cc \
	referer.cc \
	refresh.cc \
	send-announce.cc \
	$(SNMPSOURCE) \
	squid.h \
	SquidNew.cc \
	tunnel.cc \
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
	StoreMetaUnpacker.cc \
	StoreMetaUnpacker.h \
	StoreMetaURL.cc \
	StoreMetaURL.h \
	StoreMetaVary.cc \
	StoreMetaVary.h \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	structs.h \
	SwapDir.cc \
	SwapDir.h \
	tools.cc \
	typedefs.h \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.cc \
	useragent.cc \
	wais.cc \
	wccp.cc \
	whois.cc \
	$(WIN32SOURCE)

noinst_HEADERS = ACLChecklist.cci \
	AuthUser.cci \
	AuthUser.h \
	AuthUserRequest.h \
	client_side_request.cci \
	MemBuf.cci \
	MemBuf.h \
	Store.cci \
	String.cci \
	SquidString.h \
	squid_windows.h

nodist_squid_SOURCES = \
	repl_modules.cc \
	cf_parser.h \
	globals.cc \
	string_arrays.c

squid_LDADD = \
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
	@LIB_MALLOC@ \
	@SSLLIB@ \
	-lmiscutil \
	@XTRA_LIBS@ \
	@EPOLL_LIBS@
squid_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a @STORE_OBJS@ @STORE_LINKOBJS@ \
	@DISK_LIBS@ \
	@DISK_LINKOBJS@ \
	@REPL_OBJS@ \
	@AUTH_LINKOBJS@ \
	@AUTH_OBJS@

unlinkd_SOURCES = unlinkd.cc SquidNew.cc
unlinkd_CXXFLAGS = -DUNLINK_DAEMON

pinger_SOURCES = \
	pinger.cc \
	debug.cc \
	SquidNew.cc 

dnsserver_SOURCES = dnsserver.cc SquidNew.cc
recv_announce_SOURCES = recv-announce.cc SquidNew.cc

ufsdump_SOURCES = debug.cc \
	int.cc \
	ufsdump.cc \
	store.cc \
	StoreFileSystem.cc \
	StoreMeta.cc \
	StoreMeta.h \
	StoreMetaMD5.cc \
	StoreMetaMD5.h \
	StoreMetaSTD.cc \
	StoreMetaSTD.h \
	StoreMetaUnpacker.cc \
	StoreMetaUnpacker.h \
	StoreMetaURL.cc \
	StoreMetaURL.h \
	StoreMetaVary.cc \
	StoreMetaVary.h \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	access_log.cc \
	acl.cc \
	ACLChecklist.cc \
	$(squid_ACLSOURCES) \
	asn.cc \
	authenticate.cc \
	AuthUser.cc \
	cache_cf.cc \
	CacheDigest.cc \
	cache_manager.cc \
	carp.cc \
	cbdata.cc \
	client_db.cc \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	client_side_request.h \
	clientStream.cc \
	clientStream.h \
	comm.cc \
	comm.h \
	comm_select.cc \
	comm_poll.cc \
	comm_kqueue.cc \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	$(DNSSOURCE) \
	enums.h \
	errorpage.cc \
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
	HttpRequest.h \
	icmp.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IDENT_SOURCE) \
	internal.cc \
	ipc.cc \
	ipcache.cc \
	IPInterception.cc \
	IPInterception.h \
	$(LEAKFINDERSOURCE) \
	logfile.cc \
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
	$(XPROF_STATS_SOURCE) \
	pconn.cc \
	peer_digest.cc \
	peer_select.cc \
	protos.h \
	redirect.cc \
	referer.cc \
	refresh.cc \
	send-announce.cc \
	$(SNMPSOURCE) \
	squid.h \
	$(SSL_SOURCE) \
	tunnel.cc \
	SquidNew.cc \
	stat.cc \
	StatHist.cc \
	String.cc \
	stmem.cc \
	store_io.cc \
	StoreIOBuffer.h \
	StoreIOState.cc \
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
	structs.h \
	SwapDir.cc \
	tools.cc \
	typedefs.h \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.cc \
	useragent.cc \
	wais.cc \
	wccp.cc \
	whois.cc \
	$(WIN32SOURCE)
ufsdump_LDADD = \
	-L../lib \
	@XTRA_OBJS@ \
	@REPL_OBJS@ \
	@STORE_OBJS@ \
	@AUTH_OBJS@ \
	@CRYPTLIB@ \
	@REGEXLIB@ \
	@SNMPLIB@ \
	@LIB_MALLOC@ \
	@SSLLIB@ \
	-lmiscutil \
	@XTRA_LIBS@ \
	@EPOLL_LIBS@
ufsdump_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a
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
	mime.conf.default

data_DATA = \
	mib.txt

LDADD = -L../lib -lmiscutil @XTRA_LIBS@ @EPOLL_LIBS@

DISKIODIST = \
	DiskIO/DiskFile.h \
	DiskIO/DiskIOStrategy.h \
	DiskIO/IORequestor.h \
	DiskIO/DiskIOModule.h \
	DiskIO/ReadRequest.h

EXTRA_DIST = \
	cf_gen_defines \
	cf.data.pre \
	mk-globals-c.pl \
	mk-string-arrays.pl \
	repl_modules.sh \
	mib.txt \
	mime.conf.default \
	$(DISKIODIST)

libAIO_a_SOURCES = \
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
	DiskIO/DiskThreads/aiops.cc \
	DiskIO/DiskThreads/async_io.cc \
	DiskIO/DiskThreads/DiskThreads.h \
	DiskIO/DiskThreads/DiskThreadsDiskFile.cc \
	DiskIO/DiskThreads/DiskThreadsDiskFile.h \
	DiskIO/DiskThreads/DiskThreadsDiskIOModule.h \
	DiskIO/DiskThreads/DiskThreadsIOStrategy.cc \
	DiskIO/DiskThreads/DiskThreadsIOStrategy.h

DiskIO_DiskDaemon_diskd_SOURCES = DiskIO/DiskDaemon/diskd.cc 
DiskIO_DiskDaemon_diskd_LDADD = $(top_builddir)/lib/libmiscutil.a @XTRA_LIBS@


DEFAULT_PREFIX		= $(prefix)
DEFAULT_CONFIG_FILE     = $(sysconfdir)/squid.conf
DEFAULT_MIME_TABLE	= $(sysconfdir)/mime.conf
DEFAULT_DNSSERVER       = $(libexecdir)/`echo dnsserver | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_LOG_PREFIX	= $(localstatedir)/logs
DEFAULT_CACHE_LOG       = $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG      = $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG       = $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_PID_FILE        = $(DEFAULT_LOG_PREFIX)/squid.pid
DEFAULT_SWAP_DIR        = $(localstatedir)/cache
DEFAULT_PINGER		= $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_UNLINKD		= $(libexecdir)/`echo unlinkd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_DISKD		= $(libexecdir)/`echo diskd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_ICON_DIR	= $(datadir)/icons
DEFAULT_ERROR_DIR	= $(datadir)/errors/@ERR_DEFAULT_LANGUAGE@
DEFAULT_MIB_PATH	= $(datadir)/mib.txt
DEFAULT_HOSTS		= @OPT_DEFAULT_HOSTS@

DEFS = @DEFS@ -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\"

$(OBJS): $(top_srcdir)/include/version.h ../include/autoconf.h

snmp_core.o snmp_agent.o: ../snmplib/libsnmp.a $(top_srcdir)/include/cache_snmp.h

globals.cc: globals.h mk-globals-c.pl
	$(PERL) $(srcdir)/mk-globals-c.pl < $(srcdir)/globals.h > $@

string_arrays.c: enums.h mk-string-arrays.pl
	$(PERL) $(srcdir)/mk-string-arrays.pl < $(srcdir)/enums.h > $@

cache_diff: cache_diff.o debug.o globals.o store_key_md5.o
	$(CC) -o $@ $(LDFLAGS) $@.o debug.o globals.o store_key_md5.o $(STD_APP_LIBS)

test_cache_digest: test_cache_digest.o CacheDigest.o debug.o globals.o store_key_md5.o
	$(CC) -o $@ $(LDFLAGS) $@.o CacheDigest.o debug.o globals.o store_key_md5.o $(STD_APP_LIBS)

## If autodependency works well this is not needed anymore
cache_cf.o: cf_parser.h

squid.conf.default: cf_parser.h
	$(SHELL) -c "test -f squid.conf.default || ./cf_gen cf.data"

cf_parser.h: cf.data cf_gen$(EXEEXT)
	./cf_gen cf.data 

cf_gen_defines.h: $(srcdir)/cf_gen_defines $(srcdir)/cf.data.pre
	awk -f $(srcdir)/cf_gen_defines <$(srcdir)/cf.data.pre >cf_gen_defines.h


## FIXME: generate a sed command file from configure. Then this doesn't
## depend on the Makefile. 
cf.data: cf.data.pre Makefile
	sed "\
	s%@DEFAULT_MIME_TABLE@%$(DEFAULT_MIME_TABLE)%g;\
	s%@DEFAULT_DNSSERVER@%$(DEFAULT_DNSSERVER)%g;\
	s%@DEFAULT_UNLINKD@%$(DEFAULT_UNLINKD)%g;\
	s%@DEFAULT_PINGER@%$(DEFAULT_PINGER)%g;\
	s%@DEFAULT_DISKD@%$(DEFAULT_DISKD)%g;\
	s%@DEFAULT_CACHE_LOG@%$(DEFAULT_CACHE_LOG)%g;\
	s%@DEFAULT_ACCESS_LOG@%$(DEFAULT_ACCESS_LOG)%g;\
	s%@DEFAULT_STORE_LOG@%$(DEFAULT_STORE_LOG)%g;\
	s%@DEFAULT_PID_FILE@%$(DEFAULT_PID_FILE)%g;\
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

DISTCLEANFILES = cf_gen_defines.h cf.data cf_parser.h squid.conf.default \
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

TESTSOURCES=../test-suite/test_tools.cc

check_PROGRAMS+=tests/testAuth
tests_testAuth_SOURCES= tests/testAuth.cc tests/testMain.cc  tests/testAuth.h $(TESTSOURCES) \
	AuthScheme.cc globals.cc authenticate.cc AuthUser.cc AuthUserRequest.cc AuthConfig.cc \
	tests/stub_acl.cc tests/stub_cache_cf.cc \
	tests/stub_helper.cc cbdata.cc String.cc tests/stub_cache_manager.cc \
	tests/stub_store.cc HttpHeaderTools.cc HttpHeader.cc acl.cc event.cc mem.cc \
	MemBuf.cc HttpHdrContRange.cc Packer.cc ACLChecklist.cc HttpHdrCc.cc HttpHdrSc.cc \
	HttpHdrScTarget.cc url.cc ACLProxyAuth.cc ACLRegexData.cc ACLUserData.cc \
	StatHist.cc HttpHdrRange.cc ETag.cc tests/stub_errorpage.cc \
	tests/stub_HttpRequest.cc
##	acl.cc cache_cf.cc tools.cc \
##	helper.cc String.cc cbdata.cc HttpHeaderTools.cc store.cc cache_manager.cc \
##	HttpHeader.cc url.cc event.cc mem.cc HttpRequest.cc Packer.cc access_log.cc \
##	MemBuf.cc StatHist.cc logfile.cc

tests_testAuth_LDADD= \
	@AUTH_LINKOBJS@ @AUTH_OBJS@ \
	-L../lib -lmiscutil \
	@SQUID_CPPUNIT_LA@
tests_testAuth_LDFLAGS = $(LIBADD_DL)
tests_testAuth_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	@AUTH_LINKOBJS@ \
	@AUTH_OBJS@ \
	@SQUID_CPPUNIT_LA@
