#
#  Makefile for the Squid Object Cache server
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects
if USE_DNSSERVER
DNSSOURCE = dns.cc
DNSSERVER = dnsserver
else
DNSSOURCE = dns_internal.cc
DNSSERVER =
endif

DNSSOURCE += \
	DnsLookupDetails.h \
	DnsLookupDetails.cc

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

SUBDIRS	= base acl fs repl auth ip icmp ident

if USE_ADAPTATION
SUBDIRS += adaptation
endif

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

SSL_ALL_SOURCE = \
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

EXTRA_LIBRARIES = libAIO.a libBlocking.a libDiskDaemon.a libDiskThreads.a
noinst_LIBRARIES = $(DISK_LIBS)
noinst_LTLIBRARIES = libsquid.la

# libraries used by many targets
COMMON_LIBS = \
	base/libbase.la \
	libsquid.la \
	auth/libacls.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	auth/libauth.la \
	acl/libapi.la \
	ip/libip.la \
	fs/libfs.la

EXTRA_PROGRAMS = \
	DiskIO/DiskDaemon/diskd \
	unlinkd \
	dnsserver \
	recv-announce \
	tests/testUfs \
	tests/testCoss \
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
	$(DNSSERVER) \
	$(DISK_PROGRAMS) \
	$(UNLINKD)

cf_gen_SOURCES = cf_gen.cc
nodist_cf_gen_HEADER = cf_gen_defines.h
cf_gen_LDADD= \
	../compat/libcompat.la \
	-L../lib -lmiscutil \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(XTRA_LIBS)
cf_gen.$(OBJEXT): cf_gen_defines.h

## cf_gen.cc needs src/cf_gen_defines.h
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
	$(SSL_ALL_SOURCE) \
	$(WIN32_ALL_SOURCE) \
	$(LOADABLE_MODULES_SOURCES) \
	DiskIO/DiskThreads/aiops.cc \
	DiskIO/DiskThreads/aiops_win32.cc

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
	SquidConfig.cc \
        TextException.cc \
        TextException.h

squid_SOURCES = \
	$(ACL_REGISTRATION_SOURCES) \
	access_log.cc \
	AccessLogEntry.h \
	AsyncEngine.cc \
	AsyncEngine.h \
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
	ClientInfo.h \
	BodyPipe.cc \
	BodyPipe.h \
	ClientInfo.h \
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
	errorpage.h \
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
	HttpStatusCode.h \
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
	ICP.h \
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	multicast.cc \
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
	SquidMath.h \
	SquidMath.cc \
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

noinst_HEADERS = \
	client_side_request.cci \
	MemBuf.cci \
	MemBuf.h \
	Store.cci \
	StoreEntryStream.h \
	String.cci \
	SquidString.h \
	SquidTime.h

nodist_squid_SOURCES = \
	$(DISKIO_GEN_SOURCE) \
	repl_modules.cc \
	cf_parser.h \
	globals.cc \
	string_arrays.c

squid_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
        ../compat/libcompat.la \
	-L../lib \
	$(XTRA_OBJS) \
	$(DISK_LINKOBJS) \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	$(CRYPTLIB) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(SSLLIB) \
	-lmiscutil \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(XTRA_LIBS)
squid_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	$(DISK_LIBS) \
	$(DISK_LINKOBJS) \
	$(REPL_OBJS) \
	$(SNMPLIB) \
	${ADAPTATION_LIBS} \
	$(ESI_LOCAL_LIBS) \
	$(COMMON_LIBS)

if USE_LOADABLE_MODULES
squid_SOURCES += $(LOADABLE_MODULES_SOURCES)
squid_LDADD += \
	$(LIBLTDL)
squid_LDFLAGS = \
	-export-dynamic -dlopen force
# when static module linking is supported and enabled:
# squid_LDFLAGS = \
#         -all-static -dlopen self
#
endif


unlinkd_SOURCES = unlinkd_daemon.cc SquidNew.cc

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
	int.cc \
	mem.cc \
	MemBuf.cc \
	MemBuf.cci \
	MemBuf.h \
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
	dlink.h \
	dlink.cc \
	HttpRequestMethod.cc \
	RemovalPolicy.cc \
	squid.h \
	$(WIN32_SOURCE) \
	tests/stub_fd.cc
ufsdump_LDADD = \
	$(COMMON_LIBS) \
	$(XTRA_OBJS) \
	$(REPL_OBJS) \
	$(CRYPTLIB) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	$(SSLLIB) \
	-L$(top_builddir)/lib -lmiscutil \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(XTRA_LIBS)
ufsdump_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	$(COMMON_LIBS) \
	$(DISK_LIBS) \
	$(DISK_LINKOBJS) \
	$(REPL_OBJS)

nodist_ufsdump_SOURCES = \
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

LDADD = $(COMMON_LIBS)\
	-L../lib \
	-lmiscutil \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(XTRA_LIBS)

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

libDiskDaemon_a_SOURCES = \
		DiskIO/DiskDaemon/DiskdFile.cc \
		DiskIO/DiskDaemon/DiskdFile.h \
		DiskIO/DiskDaemon/DiskdIOStrategy.cc \
		DiskIO/DiskDaemon/DiskdIOStrategy.h \
		DiskIO/DiskDaemon/diomsg.h \
		DiskIO/DiskDaemon/DiskDaemonDiskIOModule.cc \
		DiskIO/DiskDaemon/DiskDaemonDiskIOModule.h

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

DiskIO_DiskDaemon_diskd_SOURCES = DiskIO/DiskDaemon/diskd.cc 
DiskIO_DiskDaemon_diskd_LDADD = $(top_builddir)/lib/libmiscutil.a $(XTRA_LIBS)


DEFAULT_HTTP_PORT	= $(CACHE_HTTP_PORT)
DEFAULT_ICP_PORT	= $(CACHE_ICP_PORT)
DEFAULT_PREFIX		= $(prefix)
DEFAULT_CONFIG_DIR	= $(sysconfdir)
DEFAULT_CONFIG_FILE     = $(DEFAULT_CONFIG_DIR)/squid.conf
DEFAULT_MIME_TABLE	= $(DEFAULT_CONFIG_DIR)/mime.conf
DEFAULT_DNSSERVER       = $(libexecdir)/`echo dnsserver | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_LOG_PREFIX	= $(DEFAULT_LOG_DIR)
DEFAULT_CACHE_LOG       = $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG      = $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG       = $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_PID_FILE        = $(DEFAULT_PIDFILE)
DEFAULT_NETDB_FILE      = $(DEFAULT_LOG_PREFIX)/netdb.state
DEFAULT_SWAP_DIR        = $(localstatedir)/cache
DEFAULT_PINGER		= $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_UNLINKD		= $(libexecdir)/`echo unlinkd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_DISKD		= $(libexecdir)/`echo diskd | sed '$(transform);s/$$/$(EXEEXT)/'`
DEFAULT_ICON_DIR	= $(datadir)/icons
DEFAULT_ERROR_DIR	= $(datadir)/errors
DEFAULT_HOSTS		= $(OPT_DEFAULT_HOSTS)

# Make location configure settings available to the code
DEFS += -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\" -DDEFAULT_SQUID_DATA_DIR=\"$(datadir)\" -DDEFAULT_SQUID_CONFIG_DIR=\"$(sysconfdir)\"

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
squid.conf.default squid.conf.documented: cf_parser.h
	true

cf_parser.h: cf.data cf_gen$(EXEEXT)
	./cf_gen cf.data $(srcdir)/cf.data.depend

cf_gen_defines.h: $(srcdir)/cf_gen_defines $(srcdir)/cf.data.pre
	$(AWK) -f $(srcdir)/cf_gen_defines <$(srcdir)/cf.data.pre >cf_gen_defines.h


## FIXME: generate a sed command file from configure. Then this doesn't
## depend on the Makefile.
cf.data: cf.data.pre Makefile
	sed \
	-e "s%[@]DEFAULT_HTTP_PORT[@]%$(DEFAULT_HTTP_PORT)%g" \
	-e "s%[@]DEFAULT_ICP_PORT[@]%$(DEFAULT_ICP_PORT)%g" \
	-e "s%[@]DEFAULT_CACHE_EFFECTIVE_USER[@]%${CACHE_EFFECTIVE_USER}%g" \
	-e "s%[@]DEFAULT_MIME_TABLE[@]%$(DEFAULT_MIME_TABLE)%g" \
	-e "s%[@]DEFAULT_DNSSERVER[@]%$(DEFAULT_DNSSERVER)%g" \
	-e "s%[@]DEFAULT_UNLINKD[@]%$(DEFAULT_UNLINKD)%g" \
	-e "s%[@]DEFAULT_PINGER[@]%$(DEFAULT_PINGER)%g" \
	-e "s%[@]DEFAULT_DISKD[@]%$(DEFAULT_DISKD)%g" \
	-e "s%[@]DEFAULT_CACHE_LOG[@]%$(DEFAULT_CACHE_LOG)%g" \
	-e "s%[@]DEFAULT_ACCESS_LOG[@]%$(DEFAULT_ACCESS_LOG)%g" \
	-e "s%[@]DEFAULT_STORE_LOG[@]%$(DEFAULT_STORE_LOG)%g" \
	-e "s%[@]DEFAULT_PID_FILE[@]%$(DEFAULT_PID_FILE)%g" \
	-e "s%[@]DEFAULT_NETDB_FILE[@]%$(DEFAULT_NETDB_FILE)%g" \
	-e "s%[@]DEFAULT_SWAP_DIR[@]%$(DEFAULT_SWAP_DIR)%g" \
	-e "s%[@]DEFAULT_ICON_DIR[@]%$(DEFAULT_ICON_DIR)%g" \
	-e "s%[@]DEFAULT_CONFIG_DIR[@]%$(DEFAULT_CONFIG_DIR)%g" \
	-e "s%[@]DEFAULT_PREFIX[@]%$(DEFAULT_PREFIX)%g" \
	-e "s%[@]DEFAULT_HOSTS[@]%$(DEFAULT_HOSTS)%g" \
	-e "s%[@]IPV6_ONLY_SETTING[@]%$(SET_IPV6_SETTINGS)%g" \
	-e "s%[@]SQUID[@]%SQUID\ $(VERSION)%g" \
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

uninstall-local: squid.conf.default
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_MIME_TABLE) $(srcdir)/mime.conf.default
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_CONFIG_FILE) squid.conf.default

CLEANFILES += cf_gen_defines.h cf.data cf_parser.h squid.conf.default squid.conf.documented \
	globals.cc string_arrays.c repl_modules.cc DiskIO/DiskIOModules_gen.cc \
	test_tools.cc *.a

test_tools.cc: $(top_srcdir)/test-suite/test_tools.cc
	cp $(top_srcdir)/test-suite/test_tools.cc .

# stock tools for unit tests - library independent versions of dlink_list 
# etc.
# globals.cc is needed by test_tools.cc.
# Neither of these should be disted from here.
TESTSOURCES= \
	test_tools.cc \
	globals.cc

# sources needed by those tests that need event.cc; incomplete
TEST_CALL_SOURCES = \
	event.cc


check_PROGRAMS+= tests/testAuth \
	tests/testACLMaxUserIP \
	tests/testBoilerplate \
	tests/testCacheManager \
	tests/testDiskIO \
	tests/testEvent \
	tests/testEventLoop \
	tests/test_http_range \
	tests/testHttpReply \
	tests/testHttpRequest \
	tests/testStore \
	tests/testString \
	tests/testURL \
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
#	-L../lib -lmiscutil
#tests_testX_DEPENDENCIES= $(SQUID_CPPUNIT_LA) \
#	$(top_builddir)/lib/libmiscutil.a


# - add other component .(h|cc) files needed to link and run tests
tests_testHttpReply_SOURCES=\
	tests/testHttpReply.h \
	tests/testHttpReply.cc \
	tests/testMain.cc \
	cbdata.h \
	cbdata.cc \
	ETag.cc \
	HttpBody.cc \
	HttpHdrCc.cc \
	HttpHdrContRange.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.h \
	HttpHdrSc.cc \
	HttpHdrScTarget.h \
	HttpHdrScTarget.cc \
	HttpHeader.h \
	HttpHeader.cc \
	HttpHeaderMask.h \
	HttpHeaderTools.cc \
	HttpMsg.h \
	HttpMsg.cc \
	HttpReply.h \
	HttpReply.cc \
	HttpStatusCode.h \
	HttpStatusLine.h \
	HttpStatusLine.cc \
	mem.cc \
	MemBuf.h \
	MemBuf.cc \
	mime_header.cc \
	Packer.h \
	Packer.cc \
	tests/stub_cache_manager.cc \
	tests/stub_StatHist.cc \
	tests/stub_store.cc \
	SquidString.h \
	String.cc \
	SquidTime.h \
	time.cc
nodist_tests_testHttpReply_SOURCES=\
	$(TESTSOURCES)
tests_testHttpReply_LDFLAGS = $(LIBADD_DL)
tests_testHttpReply_LDADD=\
	acl/libapi.la \
	acl/libstate.la \
	auth/libauth.la \
	ip/libip.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	-L../lib -lmiscutil \
	$(XTRA_LIBS)
tests_testHttpReply_DEPENDENCIES= $(SQUID_CPPUNIT_LA) \
	$(top_builddir)/lib/libmiscutil.a

tests_testAuth_SOURCES = \
	tests/testAuth.cc tests/testMain.cc  tests/testAuth.h \
	ConfigParser.cc \
	tests/stub_acl.cc tests/stub_cache_cf.cc \
	tests/stub_helper.cc cbdata.cc String.cc \
	tests/stub_store.cc HttpHeaderTools.cc HttpHeader.cc mem.cc ClientInfo.h \
	MemBuf.cc HttpHdrContRange.cc Packer.cc HttpHdrCc.cc HttpHdrSc.cc \
	HttpHdrScTarget.cc url.cc \
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
nodist_tests_testAuth_SOURCES = \
	$(TESTSOURCES)

tests_testAuth_LDADD= \
	$(COMMON_LIBS) \
	-L../lib -lmiscutil \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testAuth_LDFLAGS = $(LIBADD_DL)
tests_testAuth_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	$(SQUID_CPPUNIT_LA)

## Tests for the ACLMaxUserIP class
## acl needs wordlist. wordlist needs MemBug
## MemBuf needs mem, MemBuf needs event,
## event needs cbdata.
## ACLMaxUserUP needs libauth.la
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
	cbdata.cc \
	ClientInfo.h \
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
nodist_tests_testACLMaxUserIP_SOURCES= \
	$(TESTSOURCES)
tests_testACLMaxUserIP_LDADD= \
	$(COMMON_LIBS) \
	-L../lib -lmiscutil \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testACLMaxUserIP_LDFLAGS = $(LIBADD_DL)
tests_testACLMaxUserIP_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

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
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testBoilerplate_LDFLAGS = $(LIBADD_DL)
tests_testBoilerplate_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)

## Tests of the CacheManager module.
tests_testCacheManager_SOURCES = \
	debug.cc \
	HttpRequest.cc \
	HttpRequestMethod.cc \
	mem.cc \
	String.cc \
	tests/testCacheManager.cc \
	tests/testCacheManager.h \
	tests/testMain.cc \
	time.cc \
	access_log.cc \
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
	ClientInfo.h \
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
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	neighbors.cc \
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
	SquidMath.h \
	SquidMath.cc \
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
	globals.cc \
	repl_modules.cc \
	string_arrays.c
tests_testCacheManager_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	$(REPL_OBJS) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testCacheManager_LDFLAGS = $(LIBADD_DL)
tests_testCacheManager_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_testDiskIO_SOURCES = \
	$(SWAP_TEST_SOURCES) \
	tests/testDiskIO.cc \
	tests/testDiskIO.h \
	tests/testMain.cc \
	tests/stub_cache_manager.cc
nodist_tests_testDiskIO_SOURCES= \
	$(SWAP_TEST_GEN_SOURCES) \
	SquidMath.cc \
	SquidMath.h
tests_testDiskIO_LDADD = \
	$(SWAP_TEST_LDADD) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	$(COMMON_LIBS) \
	SquidConfig.o \
	$(XTRA_LIBS)

tests_testDiskIO_LDFLAGS = $(LIBADD_DL)
tests_testDiskIO_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	$(DISK_LIBS) \
	$(SWAP_TEST_DS) \
	$(SQUID_CPPUNIT_LA)

## Tests of the Even module.
tests_testEvent_SOURCES = \
	debug.cc \
	EventLoop.h \
	EventLoop.cc \
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
	ClientInfo.h \
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
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	neighbors.cc \
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
	SquidMath.h \
	SquidMath.cc \
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
	globals.cc \
	repl_modules.cc \
	string_arrays.c
tests_testEvent_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	$(REPL_OBJS) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testEvent_LDFLAGS = $(LIBADD_DL)
tests_testEvent_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

## Tests of the EventLoop module.
tests_testEventLoop_SOURCES = \
	debug.cc \
	EventLoop.h \
	EventLoop.cc \
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
	ClientInfo.h \
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
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	neighbors.cc \
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
	SquidMath.h \
	SquidMath.cc \
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
	globals.cc \
	repl_modules.cc \
	string_arrays.c
tests_testEventLoop_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	$(REPL_OBJS) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testEventLoop_LDFLAGS = $(LIBADD_DL)
tests_testEventLoop_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_test_http_range_SOURCES = \
	tests/test_http_range.cc \
	access_log.cc \
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
	ClientInfo.h \
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
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	multicast.cc \
	neighbors.cc \
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
	SquidMath.h \
	SquidMath.cc \
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
	globals.cc \
	repl_modules.cc \
	string_arrays.c
tests_test_http_range_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	$(REPL_OBJS) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_test_http_range_LDFLAGS = $(LIBADD_DL)
tests_test_http_range_DEPENDENCIES = \
	$(SQUID_CPPUNIT_LA)


## Tests of the HttpRequest module.
tests_testHttpRequest_SOURCES = \
	debug.cc \
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
	ClientInfo.h \
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
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	neighbors.cc \
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
	SquidMath.h \
	SquidMath.cc \
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
	globals.cc \
	repl_modules.cc \
	string_arrays.c
tests_testHttpRequest_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	$(REPL_OBJS) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(REGEXLIB) \
	$(SNMPLIB) \
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testHttpRequest_LDFLAGS = $(LIBADD_DL)
tests_testHttpRequest_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

# TODO:mime.cc drags in HttpReply.cc
# delay pools need client_side_request.cc
# store_key_md5 wants the method.
STORE_TEST_SOURCES=\
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
	Parsing.cc \
	ConfigOption.cc \
	SwapDir.cc \
	tests/stub_acl.cc tests/stub_cache_cf.cc \
	tests/stub_helper.cc cbdata.cc String.cc \
	tests/stub_comm.cc \
	tests/stub_client_side_request.cc \
	tests/stub_http.cc \
	mem_node.cc \
	stmem.cc \
	tests/stub_mime.cc \
	HttpHeaderTools.cc HttpHeader.cc mem.cc  ClientInfo.h \
	MemBuf.cc HttpHdrContRange.cc Packer.cc HttpHdrCc.cc HttpHdrSc.cc \
	HttpHdrScTarget.cc url.cc \
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

STORE_TEST_GEN_SOURCES = \
	$(TESTSOURCES) \
	string_arrays.c

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

nodist_tests_testStore_SOURCES= \
	$(STORE_TEST_GEN_SOURCES) \
	SquidMath.cc \
	SquidMath.h

tests_testStore_LDADD= \
	$(COMMON_LIBS) \
	-L../lib -lmiscutil \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testStore_LDFLAGS = $(LIBADD_DL)
tests_testStore_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	$(SQUID_CPPUNIT_LA)

## string needs mem.cc.
## mem.cc needs ClientInfo.h
## libsquid pulls in SquidConfig and children. stub them.
tests_testString_SOURCES = \
	ClientInfo.h \
	mem.cc \
	String.cc \
	tests/testMain.cc \
	tests/testString.cc \
	tests/testString.h \
	tests/stub_cache_manager.cc \
	time.cc
nodist_tests_testString_SOURCES = \
	$(TESTSOURCES)
tests_testString_LDADD = \
	$(COMMON_LIBS) \
	-L../lib -lmiscutil \
	$(REGEXLIB) \
	$(SQUID_CPPUNIT_LIBS) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testString_LDFLAGS = $(LIBADD_DL)
tests_testString_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a \
	$(SQUID_CPPUNIT_LA)

SWAP_TEST_SOURCES = \
	tests/stub_internal.cc \
	tests/stub_CommIO.cc \
	tests/stub_store_rebuild.cc \
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

SWAP_TEST_GEN_SOURCES = \
	$(STORE_TEST_GEN_SOURCES) \
	$(DISKIO_GEN_SOURCE)

SWAP_TEST_LDADD = \
	$(REGEXLIB) \
	$(COMMON_LIBS) \
	$(REPL_OBJS) \
	$(DISK_LIBS) \
	$(DISK_OS_LIBS) \
	-L../lib -lmiscutil \
	acl/libapi.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(XTRA_LIBS)
SWAP_TEST_DS =\
	$(top_builddir)/lib/libmiscutil.a \
	repl_modules.o \
	$(DISK_LIBS) \
	$(COMMON_LIBS) \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)

tests_testUfs_SOURCES = \
	tests/testUfs.cc \
	tests/testMain.cc \
	tests/testUfs.h \
	tests/stub_cache_manager.cc \
	$(SWAP_TEST_SOURCES)
nodist_tests_testUfs_SOURCES = \
	$(SWAP_TEST_GEN_SOURCES) \
	SquidMath.cc \
	SquidMath.h
tests_testUfs_LDADD = \
	$(SWAP_TEST_LDADD) \
	$(COMMON_LIBS) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testUfs_LDFLAGS = $(LIBADD_DL)
tests_testUfs_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testCoss_SOURCES = \
	tests/testCoss.cc \
	tests/testMain.cc \
	tests/testCoss.h \
	tests/stub_cache_manager.cc \
	$(SWAP_TEST_SOURCES)
nodist_tests_testCoss_SOURCES = \
	$(SWAP_TEST_GEN_SOURCES)
tests_testCoss_LDADD = \
	libsquid.la \
	$(SWAP_TEST_LDADD) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testCoss_LDFLAGS = $(LIBADD_DL)
tests_testCoss_DEPENDENCIES = \
	$(SWAP_TEST_DS)

tests_testNull_SOURCES = \
	tests/testNull.cc \
	tests/testMain.cc \
	tests/testNull.h \
	$(SWAP_TEST_SOURCES)
nodist_tests_testNull_SOURCES = \
	$(SWAP_TEST_GEN_SOURCES)
tests_testNull_LDADD = \
	$(SWAP_TEST_LDADD) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testNull_LDFLAGS = $(LIBADD_DL)
tests_testNull_DEPENDENCIES = \
	$(SWAP_TEST_DS)

## Tests of the URL module.
## TODO: Trim this down once the insanity is over.
tests_testURL_SOURCES = \
	debug.cc \
	url.cc \
	URLScheme.cc \
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
	ClientInfo.h \
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
	icp_v2.cc \
	icp_v3.cc \
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
	mime_header.cc \
	neighbors.cc \
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
	SquidMath.h \
	SquidMath.cc \
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
	globals.cc \
	repl_modules.cc \
	string_arrays.c
tests_testURL_LDADD = \
	$(COMMON_LIBS) \
	icmp/libicmp.la icmp/libicmp-core.la \
	$(REGEXLIB) \
	$(REPL_OBJS) \
	${ADAPTATION_LIBS} \
	$(ESI_LIBS) \
	$(SNMPLIB) \
	-L../lib -lmiscutil \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(SSLLIB) \
	$(XTRA_LIBS)
tests_testURL_LDFLAGS = $(LIBADD_DL)
tests_testURL_DEPENDENCIES =  $(top_builddir)/lib/libmiscutil.a \
	$(REPL_OBJS) \
	$(SQUID_CPPUNIT_LA)


TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/*.h $(srcdir)/DiskIO/*.h $(srcdir)/DiskIO/*/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)/DiskIO" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)/DiskIO/AIO" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)/DiskIO/Blocking" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)/DiskIO/DiskDaemon" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)/DiskIO/DiskThreads" || exit 1
## src/repl/ has no .h files and its own makefile.

CLEANFILES += testHeaders
.PHONY: testHeaders

