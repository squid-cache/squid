## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

DNSSOURCE = \
	dns_internal.cc

STOREMETA_SOURCE = \
	StoreMeta.cc \
	StoreMeta.h \
	StoreMetaMD5.cc \
	StoreMetaMD5.h \
	StoreMetaSTD.cc \
	StoreMetaSTD.h \
	StoreMetaSTDLFS.cc \
	StoreMetaSTDLFS.h \
	StoreMetaObjSize.h \
	StoreMetaURL.cc \
	StoreMetaURL.h \
	StoreMetaVary.cc \
	StoreMetaVary.h

LOADABLE_MODULES_SOURCES = \
	LoadableModule.cc \
	LoadableModule.h \
	LoadableModules.cc \
	LoadableModules.h

SUBDIRS = mem base anyp helper dns ftp parser comm error eui acl format clients sbuf servers fs repl store DiskIO proxyp
DIST_SUBDIRS = mem base anyp helper dns ftp parser comm error eui acl format clients sbuf servers fs repl store DiskIO proxyp

if ENABLE_AUTH
SUBDIRS += auth
AUTH_LIBS= auth/libauth.la
AUTH_ACL_LIBS= auth/libacls.la
endif
DIST_SUBDIRS += auth

SUBDIRS	+= http ip icmp ident log ipc mgr
DIST_SUBDIRS += http ip icmp ident log ipc mgr

SSL_LIBS=
if ENABLE_SSL
SUBDIRS += ssl
SSL_LIBS += \
	ssl/libsslsquid.la \
	ssl/libsslutil.la
endif
DIST_SUBDIRS += ssl security
SUBDIRS += security

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

if ENABLE_ADAPTATION
SUBDIRS += adaptation
endif
DIST_SUBDIRS += adaptation

if ENABLE_ESI
SUBDIRS += esi
ESI_LIBS = \
	esi/libesi.la \
	$(top_builddir)/lib/libTrie/libTrie.a \
	$(XMLLIB) \
	$(EXPATLIB)
else
ESI_LIBS =
endif
DIST_SUBDIRS += esi

DELAY_POOL_ALL_SOURCE = \
	BandwidthBucket.cc \
	BandwidthBucket.h \
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
	MessageBucket.cc \
	MessageBucket.h \
	MessageDelayPools.h \
	MessageDelayPools.cc \
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

if ENABLE_LEAKFINDER
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

if ENABLE_WIN32_IPC
IPC_SOURCE = SquidIpc.h ipc_win32.cc
else
IPC_SOURCE = SquidIpc.h ipc.cc
endif

noinst_LTLIBRARIES = libsquid.la

EXTRA_PROGRAMS = \
	unlinkd \
	recv-announce \
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
	$(UNLINKD)

cf_gen_SOURCES = cf_gen.cc
nodist_cf_gen_HEADER = cf_gen_defines.cci
## cf_gen must be stand-alone executable. It is a purely build-time executable.
cf_gen_LDADD=
cf_gen.$(OBJEXT): cf_gen_defines.cci

## cf_gen.cc needs src/cf_gen_defines.cci
AM_CPPFLAGS += -I$(top_builddir)/src


ACL_REGISTRATION_SOURCES = \
	AclRegs.cc \
	AuthReg.cc

# common library for all the binaries and tests. This is kindof a catch all
# and smaller libraries split from this are encouraged. Using lt convenience
# libraries, dependencies should not be a problem either.
libsquid_la_SOURCES = \
	CommCalls.cc \
	CommCalls.h \
	DescriptorSet.cc \
	DescriptorSet.h \
	SquidConfig.cc \
	SquidConfig.h \
	comm.cc \
	comm.h

squid_SOURCES = \
	$(ACL_REGISTRATION_SOURCES) \
	$(DELAY_POOL_SOURCE) \
	$(DNSSOURCE) \
	$(HTCPSOURCE) \
	$(IPC_SOURCE) \
	$(LEAKFINDERSOURCE) \
	$(SNMP_SOURCE) \
	$(STOREMETA_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	$(WINSVC_SOURCE) \
	$(XPROF_STATS_SOURCE) \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	AsyncEngine.cc \
	AsyncEngine.h \
	AuthReg.h \
	BodyPipe.cc \
	BodyPipe.h \
	CacheDigest.cc \
	CacheDigest.h \
	CacheManager.h \
	CachePeer.cc \
	CachePeer.h \
	ClientInfo.h \
	ClientRequestContext.h \
	CollapsedForwarding.cc \
	CollapsedForwarding.h \
	CollapsingHistory.h \
	CommRead.h \
	CommandLine.cc \
	CommandLine.h \
	CompletionDispatcher.cc \
	CompletionDispatcher.h \
	ConfigOption.cc \
	ConfigParser.cc \
	ConfigParser.h \
	CpuAffinity.cc \
	CpuAffinity.h \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	Debug.h \
	Downloader.cc \
	Downloader.h \
	ETag.cc \
	ETag.h \
	EventLoop.cc \
	EventLoop.h \
	ExternalACL.h \
	ExternalACLEntry.cc \
	ExternalACLEntry.h \
	FadingCounter.cc \
	FadingCounter.h \
	FileMap.h \
	FwdState.cc \
	FwdState.h \
	Generic.h \
	HappyConnOpener.cc \
	HappyConnOpener.h \
	HierarchyLogEntry.h \
	HttpBody.cc \
	HttpBody.h \
	HttpControlMsg.cc \
	HttpControlMsg.h \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrContRange.h \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrSc.h \
	HttpHdrScTarget.cc \
	HttpHdrScTarget.h \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderMask.h \
	HttpHeaderRange.h \
	HttpHeaderStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	HttpReply.h \
	HttpRequest.cc \
	HttpRequest.h \
	HttpUpgradeProtocolAccess.cc \
	HttpUpgradeProtocolAccess.h \
	ICP.h \
	Instance.cc \
	Instance.h \
	IoStats.h \
	LogTags.cc \
	LogTags.h \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemObject.h \
	MemStore.cc \
	MemStore.h \
	MessageSizes.h \
	NeighborTypeDomainList.h \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	Parsing.h \
	PeerDigest.h \
	PeerPoolMgr.cc \
	PeerPoolMgr.h \
	PeerSelectState.h \
	PingData.h \
	Pipeline.cc \
	Pipeline.h \
	RefreshPattern.h \
	RemovalPolicy.cc \
	RemovalPolicy.h \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	SBufStatsAction.cc \
	SBufStatsAction.h \
	SquidMath.cc \
	SquidMath.h \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	Store.h \
	StoreClient.h \
	StoreFileSystem.cc \
	StoreFileSystem.h \
	StoreIOBuffer.h \
	StoreIOState.cc \
	StoreIOState.h \
	StoreMetaUnpacker.cc \
	StoreMetaUnpacker.h \
	StoreSearch.h \
	StoreStats.cc \
	StoreStats.h \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	StrList.cc \
	StrList.h \
	String.cc \
	TimeOrTag.h \
	Transients.cc \
	Transients.h \
	XactionInitiator.cc \
	XactionInitiator.h \
	XactionStep.h \
	cache_cf.cc \
	cache_cf.h \
	cache_manager.cc \
	carp.cc \
	carp.h \
	cbdata.cc \
	cbdata.h \
	clientStream.cc \
	clientStream.h \
	clientStreamForward.h \
	client_db.cc \
	client_db.h \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_reply.h \
	client_side_request.cc \
	client_side_request.h \
	debug.cc \
	defines.h \
	dlink.cc \
	dlink.h \
	enums.h \
	errorpage.cc \
	errorpage.h \
	event.cc \
	event.h \
	external_acl.cc \
	fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	fde.h \
	filemap.cc \
	fqdncache.cc \
	fqdncache.h \
	fs_io.cc \
	fs_io.h \
	globals.h \
	gopher.cc \
	gopher.h \
	helper.cc \
	helper.h \
	hier_code.h \
	http.cc \
	http.h \
	icp_opcode.h \
	icp_v2.cc \
	icp_v3.cc \
	int.cc \
	int.h \
	internal.cc \
	internal.h \
	ipcache.cc \
	ipcache.h \
	lookup_t.h \
	main.cc \
	mem_node.cc \
	mem_node.h \
	mime.cc \
	mime.h \
	mime_header.cc \
	mime_header.h \
	multicast.cc \
	multicast.h \
	neighbors.cc \
	neighbors.h \
	pconn.cc \
	pconn.h \
	peer_digest.cc \
	peer_proxy_negotiate_auth.cc \
	peer_proxy_negotiate_auth.h \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_sourcehash.h \
	peer_userhash.cc \
	peer_userhash.h \
	protos.h \
	redirect.cc \
	redirect.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	sbuf/StringConvert.h \
	send-announce.cc \
	send-announce.h \
	stat.cc \
	stat.h \
	stmem.cc \
	stmem.h \
	store.cc \
	store_client.cc \
	store_digest.cc \
	store_digest.h \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	store_log.cc \
	store_log.h \
	store_rebuild.cc \
	store_rebuild.h \
	store_swapin.cc \
	store_swapin.h \
	store_swapmeta.cc \
	store_swapout.cc \
	swap_log_op.h \
	time.cc \
	tools.cc \
	tools.h \
	tunnel.cc \
	typedefs.h \
	urn.cc \
	urn.h \
	wccp.cc \
	wccp.h \
	wccp2.cc \
	wccp2.h \
	whois.cc \
	whois.h \
	wordlist.cc \
	wordlist.h

EXTRA_squid_SOURCES = \
	$(DELAY_POOL_ALL_SOURCE) \
	$(LOADABLE_MODULES_SOURCES) \
	$(SNMP_ALL_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_ALL_SOURCE) \
	$(all_AUTHMODULES) \
	ConfigOption.h \
	LeakFinder.cc \
	LeakFinder.h \
	ProfStats.cc \
	htcp.cc \
	htcp.h \
	ipc.cc \
	ipc_win32.cc

noinst_HEADERS = \
	MemBuf.h \
	SquidString.h \
	SquidTime.h

BUILT_SOURCES = \
	cf_gen_defines.cci \
	cf_parser.cci \
	globals.cc \
	hier_code.cc \
	icp_opcode.cc \
	lookup_t.cc \
	repl_modules.cc \
	swap_log_op.cc

CLEANFILES += $(BUILT_SOURCES)

nodist_squid_SOURCES = \
	$(BUILT_SOURCES)

squid_LDADD = \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	$(AUTH_LIBS) \
	acl/libapi.la \
	clients/libclients.la \
	servers/libservers.la \
	ftp/libftp.la \
	helper/libhelper.la \
	http/libhttp.la \
	dns/libdns.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	DiskIO/libdiskio.la \
	comm/libcomm.la \
	anyp/libanyp.la \
	security/libsecurity.la \
	$(SSL_LIBS) \
	error/liberror.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	proxyp/libproxyp.la \
	parser/libparser.la \
	eui/libeui.la \
	icmp/libicmp.la \
	log/liblog.la \
	format/libformat.la \
	sbuf/libsbuf.la \
	$(XTRA_OBJS) \
	$(REPL_OBJS) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(REGEXLIB) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SNMP_LIBS) \
	mem/libmem.la \
	store/libstore.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SSLLIB) \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(KRB5LIBS) \
	$(SYSTEMD_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

if ENABLE_LOADABLE_MODULES
squid_SOURCES += $(LOADABLE_MODULES_SOURCES)
squid_LDADD += -L$(top_builddir) $(LIBLTDL)
squid_LDFLAGS = -export-dynamic -dlopen force
## when static module linking is supported and enabled:
## squid_LDFLAGS = -all-static -dlopen self
##
## LTDL headers require their local include path...
AM_CPPFLAGS += $(INCLTDL)
endif

## Kerberos libraries require their include path...
AM_CPPFLAGS += $(KRB5INCS)


unlinkd_SOURCES = unlinkd_daemon.cc
unlinkd_LDADD = \
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
## cache_cf.cc wants store/libstore.la
## cache_cf.cc wants AnyP::PortCfg
## client_side wants client_db
## client_db wants SNMP_SOURCE
## snmp_core wants ACLStringData
## tools.cc wants ip/libip.la
## client_side.cc wants ip/libip.la
## libbase.la wants cbdata.*
## libbase.la wants MemBuf.*
ufsdump_SOURCES = \
	$(WIN32_SOURCE) \
	ClientInfo.h \
	tests/stub_HelperChildConfig.cc \
	MemBuf.cc \
	MemBuf.h \
	Parsing.h \
	RemovalPolicy.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	String.cc \
	cbdata.cc \
	cbdata.h \
	debug.cc \
	dlink.cc \
	dlink.h \
	tests/stub_fd.cc \
	fd.h \
	helper/ChildConfig.h \
	int.cc \
	int.h \
	mem/forward.h \
	store_key_md5.cc \
	store_key_md5.h \
	tests/stub_time.cc \
	ufsdump.cc
ufsdump_LDADD = \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(XTRA_OBJS) \
	$(REPL_OBJS) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(COMPAT_LIB) \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(XTRA_LIBS)
ufsdump_DEPENDENCIES = \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	DiskIO/libdiskio.la \
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

include $(srcdir)/tests/Stub.am

EXTRA_DIST = \
	cf_gen_defines \
	cf.data.pre \
	cf.data.depend \
	cf.data.sed \
	mk-globals-c.awk \
	mk-string-arrays.awk \
	repl_modules.sh \
	$(STUB_SOURCE) \
	tests/STUB.h \
	mib.txt \
	mime.conf.default

snmp_core.o snmp_agent.o: ../lib/snmplib/libsnmplib.la $(top_srcdir)/include/cache_snmp.h

globals.cc: globals.h mk-globals-c.awk
	$(AWK) -f $(srcdir)/mk-globals-c.awk < $(srcdir)/globals.h > $@ || ($(RM) -f $@ && exit 1)

## Generate files containing string arrays for various enums....
hier_code.cc: hier_code.h mk-string-arrays.awk
	$(AWK) -f $(srcdir)/mk-string-arrays.awk < $(srcdir)/hier_code.h > $@ || ($(RM) -f $@ && exit 1)

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
	$(BUILDCXX) $(BUILDCXXFLAGS) -o $@ $(srcdir)/cf_gen.cc -I$(srcdir) -I$(top_builddir)/include/ -I$(top_builddir)/src

# squid.conf.default is built by cf_gen when making cf_parser.cci
squid.conf.default squid.conf.documented: cf_parser.cci
	true

cf_parser.cci: cf.data cf_gen$(EXEEXT)
	./cf_gen$(EXEEXT) cf.data $(srcdir)/cf.data.depend

# The cf_gen_defines.cci is auto-generated and does not exist when the 
# dependencies computed. We need to add its include files (autoconf.h) here
cf_gen_defines.cci: $(srcdir)/cf_gen_defines $(srcdir)/cf.data.pre $(top_builddir)/include/autoconf.h
	$(AWK) -f $(srcdir)/cf_gen_defines <$(srcdir)/cf.data.pre >$@ || ($(RM) -f $@ && exit 1)


## TODO: generate a sed command file from configure. Then this doesn't
## depend on the Makefile.
cf.data: cf.data.pre Makefile
	sed \
	-e "s%[@]DEFAULT_HTTP_PORT[@]%$(DEFAULT_HTTP_PORT)%g" \
	-e "s%[@]DEFAULT_ICP_PORT[@]%$(DEFAULT_ICP_PORT)%g" \
	-e "s%[@]DEFAULT_CACHE_EFFECTIVE_USER[@]%$(CACHE_EFFECTIVE_USER)%g" \
	-e "s%[@]DEFAULT_MIME_TABLE[@]%$(DEFAULT_MIME_TABLE)%g" \
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
	-f $(srcdir)/cf.data.sed \
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

### Template for new Unit Test Program
## - copy template below and substitute X for class name
## - place code being tested in _SOURCES
## - place stubs etc. requiredd to link in nodist_*_SOURCES
## - add other component .(h|cc) files needed to link and run tests
##
#check_PROGRAMS += tests/testX
#tests_testX_SOURCES= \
#	tests/testX.cc \
#	tests/testX.h
#nodist_tests_testX_SOURCES= \
#	X.cc \
#	tests/stubs_as_needed.cc
#tests_testX_LDADD=\
#	$(LIBCPPUNIT_LIBS) \
#	$(COMPAT_LIB) \
#	$(XTRA_LIBS)
#tests_testX_LDFLAGS = $(LIBADD_DL)

## A demonstration test that does nothing but shows the salient points
## involved in writing tests.
check_PROGRAMS += tests/testBoilerplate
tests_testBoilerplate_SOURCES = \
	tests/testBoilerplate.cc \
	tests/testBoilerplate.h
nodist_tests_testBoilerplate_SOURCES = \
	$(TESTSOURCES)
tests_testBoilerplate_LDADD= \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testBoilerplate_LDFLAGS = $(LIBADD_DL)

# Unit Tests are listed below by sub-directory with order matching the SUBDIRS
# dependency-based list so that simpler code is tested before more complex code
# which uses it.

## Tests of mem/*

check_PROGRAMS += tests/testMem
tests_testMem_SOURCES = \
	tests/testMem.cc \
	tests/testMem.h
nodist_tests_testMem_SOURCES = \
	tests/stub_time.cc
tests_testMem_LDADD = \
	mem/libmem.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testMem_LDFLAGS = $(LIBADD_DL)

## Tests of base/*

check_PROGRAMS += tests/testCharacterSet
tests_testCharacterSet_SOURCES = \
	tests/testCharacterSet.cc \
	tests/testCharacterSet.h
nodist_tests_testCharacterSet_SOURCES = \
	base/CharacterSet.h
tests_testCharacterSet_LDADD = \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testCharacterSet_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testEnumIterator
tests_testEnumIterator_SOURCES = \
	tests/testEnumIterator.cc \
	tests/testEnumIterator.h
nodist_tests_testEnumIterator_SOURCES = \
	base/EnumIterator.h
tests_testEnumIterator_LDADD = \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEnumIterator_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testLookupTable
tests_testLookupTable_SOURCES = \
	tests/testLookupTable.cc \
	tests/testLookupTable.h
nodist_tests_testLookupTable_SOURCES = \
	tests/stub_SBufDetailedStats.cc \
	base/LookupTable.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc
tests_testLookupTable_LDADD = \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testLookupTable_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testRefCount
tests_testRefCount_SOURCES = \
	tests/testRefCount.cc \
	tests/testRefCount.h
nodist_tests_testRefCount_SOURCES = \
	base/RefCount.h
tests_testRefCount_LDADD = \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testRefCount_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testYesNoNone
tests_testYesNoNone_SOURCES = \
	tests/testYesNoNone.cc \
	tests/testYesNoNone.h
nodist_tests_testYesNoNone_SOURCES = \
	tests/stub_SBuf.cc \
	base/YesNoNone.h \
	tests/stub_debug.cc
tests_testYesNoNone_LDADD = \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testYesNoNone_LDFLAGS = $(LIBADD_DL)

## Tests of anyp/*

check_PROGRAMS += tests/testURL
tests_testURL_SOURCES = \
	tests/testURL.cc \
	tests/testURL.h \
	tests/testUriScheme.cc \
	tests/testUriScheme.h
nodist_tests_testURL_SOURCES = \
	tests/stub_HelperChildConfig.cc \
	tests/stub_HttpHeader.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_StatHist.cc \
	String.cc \
	tests/stub_access_log.cc \
	anyp/Uri.h \
	anyp/UriScheme.h \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_libhttp.cc \
	tests/stub_libmem.cc
tests_testURL_LDADD = \
	libsquid.la \
	proxyp/libproxyp.la \
	anyp/libanyp.la \
	parser/libparser.la \
	base/libbase.la \
	ip/libip.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testURL_LDFLAGS = $(LIBADD_DL)

## Tests of dns/*

check_PROGRAMS += tests/testDns
tests_testDns_SOURCES = \
	tests/testRFC1035.cc \
	tests/testRFC1035.h
nodist_tests_testDns_SOURCES=
tests_testDns_LDADD = \
	dns/libdns.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testDns_LDFLAGS = $(LIBADD_DL)

## Tests of parser/*

check_PROGRAMS += tests/testTokenizer
tests_testTokenizer_SOURCES = \
	tests/testTokenizer.cc \
	tests/testTokenizer.h
nodist_tests_testTokenizer_SOURCES = \
	tests/stub_StatHist.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	parser/Tokenizer.h
tests_testTokenizer_LDADD = \
	parser/libparser.la \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testTokenizer_LDFLAGS = $(LIBADD_DL)

## Tests of sbuf/* and String handling objects

check_PROGRAMS += tests/testSBuf
tests_testSBuf_SOURCES = \
	tests/testSBuf.cc \
	tests/testSBuf.h \
	tests/SBufFindTest.cc \
	tests/SBufFindTest.h
nodist_tests_testSBuf_SOURCES = \
	tests/stub_StatHist.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc
tests_testSBuf_LDADD = \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testSBuf_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testSBufList
tests_testSBufList_SOURCES = \
	tests/testSBufList.cc \
	tests/testSBufList.h
nodist_tests_testSBufList_SOURCES = \
	tests/stub_StatHist.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc
tests_testSBufList_LDADD = \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testSBufList_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testString
tests_testString_SOURCES = \
	tests/testString.cc \
	tests/testString.h
nodist_tests_testString_SOURCES = \
	tests/stub_SBuf.cc \
	String.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc
tests_testString_LDADD = \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testString_LDFLAGS = $(LIBADD_DL)

## Tests of fs/*

if ENABLE_FS_ROCK
check_PROGRAMS += tests/testRock
tests_testRock_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(STOREMETA_SOURCE) \
	$(UNLINKDSOURCE) \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	CollapsedForwarding.cc \
	CollapsedForwarding.h \
	ConfigOption.cc \
	ConfigParser.cc \
	ETag.cc \
	EventLoop.cc \
	FadingCounter.cc \
	FileMap.h \
	tests/stub_HelperChildConfig.cc \
	HttpBody.cc \
	HttpBody.h \
	HttpHdrCc.cc \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	tests/stub_HttpRequest.cc \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	tests/stub_Port.cc \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/testRock.cc \
	tests/testRock.h \
	tests/stub_SBufDetailedStats.cc \
	StatCounters.cc \
	StatCounters.h \
	tests/stub_StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMetaUnpacker.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	Transients.h \
	tests/stub_access_log.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cache_manager.cc \
	cbdata.cc \
	tests/stub_client_db.cc \
	tests/stub_client_side_request.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	event.cc \
	fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	fde.h \
	filemap.cc \
	fs_io.cc \
	fs_io.h \
	tests/stub_http.cc \
	tests/stub_icp.cc \
	int.cc \
	int.h \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libanyp.cc \
	tests/stub_libauth.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_liblog.cc \
	tests/stub_libmgr.cc \
	tests/stub_libsecurity.cc \
	log/access_log.h \
	mem_node.cc \
	tests/stub_mime.cc \
	mime.h \
	tests/stub_neighbors.cc \
	tests/stub_pconn.cc \
	repl_modules.h \
	tests/stub_stat.cc \
	stmem.cc \
	store.cc \
	tests/stub_store_client.cc \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	tests/stub_store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testRock_SOURCES = \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
	hier_code.cc \
	swap_log_op.cc
tests_testRock_LDADD = \
	http/libhttp.la \
	parser/libparser.la \
	libsquid.la \
	comm/libcomm.la \
	ip/libip.la \
	fs/libfs.la \
	$(COMMON_LIBS) \
	$(REPL_OBJS) \
	DiskIO/libdiskio.la \
	acl/libacls.la \
	acl/libapi.la \
	acl/libstate.la \
	anyp/libanyp.la \
	eui/libeui.la \
	$(SSL_LIBS) \
	ipc/libipc.la \
	base/libbase.la \
	mem/libmem.la \
	store/libstore.la \
	$(ADAPTATION_LIBS) \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testRock_LDFLAGS = $(AM_CPPFLAGS) $(LIBADD_DL)
else
EXTRA_DIST += \
        tests/testRock.cc \
        tests/testRock.h \
        tests/testStoreSupport.cc \
        tests/testStoreSupport.h
endif

if ENABLE_FS_UFS
check_PROGRAMS += tests/testUfs
tests_testUfs_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(STOREMETA_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	ETag.cc \
	EventLoop.cc \
	FadingCounter.cc \
	FileMap.h \
	tests/stub_HelperChildConfig.cc \
	HttpBody.cc \
	HttpBody.h \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	tests/stub_HttpRequest.cc \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	tests/stub_Port.cc \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	tests/stub_SBufDetailedStats.cc \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMetaUnpacker.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_UdsOp.cc \
	tests/testUfs.cc \
	tests/testUfs.h \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cache_manager.cc \
	cbdata.cc \
	tests/stub_client_db.cc \
	client_db.h \
	tests/stub_client_side_request.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	event.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	fde.h \
	filemap.cc \
	fs_io.cc \
	fs_io.h \
	tests/stub_helper.cc \
	tests/stub_http.cc \
	tests/stub_icp.cc \
	int.cc \
	int.h \
	tests/stub_internal.cc \
	internal.h \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libanyp.cc \
	tests/stub_libauth.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_liblog.cc \
	tests/stub_libsecurity.cc \
	log/access_log.h \
	mem_node.cc \
	tests/stub_mime.cc \
	mime.h \
	tests/stub_neighbors.cc \
	tests/stub_pconn.cc \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	tests/stub_stat.cc \
	stmem.cc \
	store.cc \
	tests/stub_store_client.cc \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	tests/stub_store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testUfs_SOURCES = \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
	hier_code.cc \
	swap_log_op.cc
tests_testUfs_LDADD = \
	http/libhttp.la \
	parser/libparser.la \
	CommCalls.o \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	mgr/libmgr.la \
	$(REPL_OBJS) \
	acl/libacls.la \
	DiskIO/libdiskio.la \
	acl/libapi.la \
	anyp/libanyp.la \
	$(SSL_LIBS) \
	ipc/libipc.la \
	comm/libcomm.la \
	dns/libdns.la \
	base/libbase.la \
	ip/libip.la \
	mem/libmem.la \
	store/libstore.la \
	$(ADAPTATION_LIBS) \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testUfs_LDFLAGS = $(LIBADD_DL)
else
EXTRA_DIST += \
	tests/testUfs.cc \
	tests/testUfs.h
endif

## Tests of store/* and Store objects

check_PROGRAMS += tests/testStore
## why so many sources? well httpHeaderTools requites ACLChecklist & friends.
## first line - what we are testing.
tests_testStore_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	ETag.cc \
	EventLoop.cc \
	FileMap.h \
	tests/stub_HelperChildConfig.cc \
	HttpBody.cc \
	HttpBody.h \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	tests/stub_HttpReply.cc \
	tests/stub_HttpRequest.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	tests/testPackableStream.cc \
	tests/testPackableStream.h \
	Parsing.cc \
	tests/stub_Port.cc \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	tests/stub_SBufDetailedStats.cc \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	tests/testStore.cc \
	tests/testStore.h \
	tests/testStoreController.cc \
	tests/testStoreController.h \
	tests/testStoreHashIndex.cc \
	tests/testStoreHashIndex.h \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_UdsOp.cc \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cache_manager.cc \
	cbdata.cc \
	tests/stub_client_side_request.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	event.cc \
	tests/stub_fatal.cc \
	fatal.h \
	tests/stub_fd.cc \
	fd.h \
	fde.h \
	filemap.cc \
	fs_io.cc \
	fs_io.h \
	tests/stub_helper.cc \
	tests/stub_http.cc \
	int.cc \
	int.h \
	tests/stub_libanyp.cc \
	tests/stub_libauth.cc \
	tests/stub_libcomm.cc \
	tests/stub_libdiskio.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libformat.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libsslsquid.cc \
	log/access_log.h \
	mem_node.cc \
	tests/stub_mime.cc \
	mime.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	tests/stub_stat.cc \
	stmem.cc \
	store.cc \
	tests/stub_store_client.cc \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	tests/stub_store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapout.cc \
	tests/stub_store_swapout.cc \
	tests/CapturingStoreEntry.h \
	tests/TestSwapDir.cc \
	tests/TestSwapDir.h \
	tests/stub_time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testStore_SOURCES = \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
	swap_log_op.cc
tests_testStore_LDADD= \
	libsquid.la \
	http/libhttp.la \
	parser/libparser.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	dns/libdns.la \
	base/libbase.la \
	ip/libip.la \
	fs/libfs.la \
	mgr/libmgr.la \
	ipc/libipc.la \
	anyp/libanyp.la \
	mem/libmem.la \
	store/libstore.la \
	sbuf/libsbuf.la \
	DiskIO/libdiskio.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	CommCalls.o \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testStore_LDFLAGS = $(LIBADD_DL)

## Tests of DiskIO/*

check_PROGRAMS += tests/testDiskIO
tests_testDiskIO_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	tests/testDiskIO.cc \
	tests/testDiskIO.h \
	tests/stub_ETag.cc \
	EventLoop.cc \
	FadingCounter.cc \
	FileMap.h \
	tests/stub_HelperChildConfig.cc \
	HttpBody.cc \
	HttpBody.h \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	tests/stub_HttpRequest.cc \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	tests/stub_MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	tests/stub_Port.cc \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/stub_SBufDetailedStats.cc \
	StatCounters.cc \
	StatCounters.h \
	tests/stub_StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_UdsOp.cc \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cache_manager.cc \
	cbdata.cc \
	tests/stub_client_db.cc \
	client_db.h \
	tests/stub_client_side_request.cc \
	client_side_request.h \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	event.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	fde.h \
	filemap.cc \
	fs_io.cc \
	fs_io.h \
	tests/stub_helper.cc \
	tests/stub_http.cc \
	tests/stub_icp.cc \
	int.cc \
	int.h \
	tests/stub_internal.cc \
	internal.h \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libanyp.cc \
	tests/stub_libauth.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_liblog.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libstore.cc \
	log/access_log.h \
	mem_node.cc \
	tests/stub_mime.cc \
	mime.h \
	tests/stub_neighbors.cc \
	tests/stub_pconn.cc \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	tests/stub_stat.cc \
	stmem.cc \
	store.cc \
	tests/stub_store_client.cc \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	tests/stub_store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	tests/stub_time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testDiskIO_SOURCES = \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
	hier_code.cc \
	swap_log_op.cc
tests_testDiskIO_LDADD = \
	libsquid.la \
	http/libhttp.la \
	parser/libparser.la \
	SquidConfig.o \
	CommCalls.o \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	comm/libcomm.la \
	ip/libip.la \
	fs/libfs.la \
	ipc/libipc.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	DiskIO/libdiskio.la \
	acl/libapi.la \
	anyp/libanyp.la \
	mgr/libmgr.la \
	$(SSL_LIBS) \
	ipc/libipc.la \
	dns/libdns.la \
	base/libbase.la \
	mem/libmem.la \
	store/libstore.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testDiskIO_LDFLAGS = $(LIBADD_DL)

## Tests of auth/*

if ENABLE_AUTH
check_PROGRAMS += tests/testACLMaxUserIP
tests_testACLMaxUserIP_SOURCES = \
	tests/testACLMaxUserIP.cc \
	tests/testACLMaxUserIP.h
nodist_tests_testACLMaxUserIP_SOURCES = \
	ConfigParser.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_HttpHeader.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_MemBuf.cc \
	Parsing.cc \
	tests/stub_StatHist.cc \
	String.cc \
	tests/stub_access_log.cc \
	tests/stub_cache_cf.cc \
	tests/stub_cbdata.cc \
	tests/stub_client_side.cc \
	tests/stub_debug.cc \
	dlink.cc \
	tests/stub_errorpage.cc \
	tests/stub_fatal.cc \
	globals.cc \
	tests/stub_libauth.cc \
	tests/stub_libhttp.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc
tests_testACLMaxUserIP_LDADD = \
	$(AUTH_ACL_LIBS) \
	acl/libapi.la \
	acl/libstate.la \
	acl/libacls.la \
	SquidConfig.o \
	ip/libip.la \
	parser/libparser.la \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testACLMaxUserIP_LDFLAGS = $(LIBADD_DL)
else
EXTRA_DIST += \
	tests/testACLMaxUserIP.cc \
	tests/testACLMaxUserIP.h
endif

## Tests of http/* and HTTP Protocol objects

check_PROGRAMS += tests/test_http_range
tests_test_http_range_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(DNSSOURCE) \
	$(HTCPSOURCE) \
	$(IPC_SOURCE) \
	$(SNMP_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AuthReg.h \
	BodyPipe.cc \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	CachePeer.cc \
	CachePeer.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	tests/stub_ETag.cc \
	tests/stub_EventLoop.cc \
	FadingCounter.cc \
	FileMap.h \
	FwdState.cc \
	FwdState.h \
	HappyConnOpener.cc \
	HappyConnOpener.h \
	HttpBody.cc \
	HttpBody.h \
	tests/stub_HttpControlMsg.cc \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	HttpRequest.cc \
	tests/stub_HttpUpgradeProtocolAccess.cc \
	IoStats.h \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	tests/stub_MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	PeerPoolMgr.cc \
	PeerPoolMgr.h \
	Pipeline.cc \
	Pipeline.h \
	RefreshPattern.h \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/stub_SBufDetailedStats.cc \
	SquidMath.cc \
	SquidMath.h \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/test_http_range.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	cache_manager.cc \
	tests/stub_carp.cc \
	carp.h \
	cbdata.cc \
	clientStream.cc \
	tests/stub_client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_request.cc \
	debug.cc \
	dlink.cc \
	dlink.h \
	errorpage.cc \
	event.cc \
	tests/stub_external_acl.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	filemap.cc \
	fqdncache.cc \
	fqdncache.h \
	fs_io.cc \
	fs_io.h \
	tests/stub_gopher.cc \
	gopher.h \
	helper.cc \
	hier_code.h \
	http.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.cc \
	int.h \
	internal.cc \
	internal.h \
	tests/stub_ipc_Forwarder.cc \
	ipcache.cc \
	tests/stub_libauth.cc \
	tests/stub_libdiskio.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libstore.cc \
	tests/stub_main_cc.cc \
	mem_node.cc \
	mime.cc \
	mime.h \
	mime_header.cc \
	mime_header.h \
	multicast.cc \
	multicast.h \
	neighbors.cc \
	neighbors.h \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.cc \
	peer_proxy_negotiate_auth.h \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_sourcehash.h \
	peer_userhash.cc \
	peer_userhash.h \
	tests/stub_redirect.cc \
	redirect.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	stat.cc \
	stat.h \
	stmem.cc \
	store.cc \
	store_client.cc \
	tests/stub_store_digest.cc \
	store_digest.h \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	store_log.cc \
	store_log.h \
	store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapin.cc \
	store_swapin.h \
	store_swapmeta.cc \
	store_swapout.cc \
	time.cc \
	tools.cc \
	tools.h \
	tests/stub_tunnel.cc \
	urn.cc \
	urn.h \
	tests/stub_wccp2.cc \
	wccp2.h \
	tests/stub_whois.cc \
	whois.h \
	wordlist.cc \
	wordlist.h
nodist_tests_test_http_range_SOURCES = \
	$(BUILT_SOURCES)
tests_test_http_range_LDADD = \
	libsquid.la \
	clients/libclients.la \
	servers/libservers.la \
	ftp/libftp.la \
	helper/libhelper.la \
	http/libhttp.la \
	parser/libparser.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	proxyp/libproxyp.la \
	parser/libparser.la \
	ip/libip.la \
	fs/libfs.la \
	anyp/libanyp.la \
	icmp/libicmp.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	ipc/libipc.la \
	dns/libdns.la \
	base/libbase.la \
	mgr/libmgr.la \
	sbuf/libsbuf.la \
	store/libstore.la \
	$(SNMP_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(LIBCPPUNIT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_test_http_range_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testHttp1Parser
tests_testHttp1Parser_SOURCES = \
	Debug.h \
	tests/stub_HelperChildConfig.cc \
	tests/testHttp1Parser.cc \
	tests/testHttp1Parser.h \
	MemBuf.cc \
	MemBuf.h \
	tests/stub_MemObject.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cache_manager.cc \
	tests/stub_cbdata.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_event.cc \
	tests/stub_libanyp.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	mime_header.cc \
	mime_header.h \
	tests/stub_stmem.cc \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	tests/stub_time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testHttp1Parser_SOURCES = \
	$(TESTSOURCES)
tests_testHttp1Parser_LDADD= \
	http/libhttp.la \
	parser/libparser.la \
	anyp/libanyp.la \
	SquidConfig.o \
	base/libbase.la \
	ip/libip.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttp1Parser_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testHttpReply
tests_testHttpReply_SOURCES = \
	ConfigParser.cc \
	tests/stub_ETag.cc \
	tests/stub_HelperChildConfig.cc \
	HttpBody.cc \
	HttpBody.h \
	HttpControlMsg.cc \
	HttpControlMsg.h \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrContRange.h \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrSc.h \
	HttpHdrScTarget.cc \
	HttpHdrScTarget.h \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderMask.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	tests/testHttpReply.cc \
	HttpReply.h \
	tests/testHttpReply.h \
	tests/stub_HttpRequest.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemBuf.h \
	Notes.cc \
	Notes.h \
	tests/stub_SBufDetailedStats.cc \
	SquidString.h \
	SquidTime.h \
	StatCounters.cc \
	StatCounters.h \
	tests/stub_StatHist.cc \
	StatHist.h \
	StrList.cc \
	StrList.h \
	String.cc \
	tests/stub_access_log.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cache_manager.cc \
	cbdata.cc \
	cbdata.h \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	tests/stub_event.cc \
	tests/stub_fatal.cc \
	fatal.h \
	tests/stub_fd.cc \
	tests/stub_libanyp.cc \
	tests/stub_libauth.cc \
	tests/stub_libcomm.cc \
	tests/stub_liberror.cc \
	tests/stub_libformat.cc \
	tests/stub_libmgr.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libsslsquid.cc \
	log/access_log.h \
	mime_header.cc \
	mime_header.h \
	repl_modules.h \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	tests/stub_time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testHttpReply_SOURCES = \
	$(TESTSOURCES) \
	hier_code.cc
tests_testHttpReply_LDADD=\
	CommCalls.o \
	http/libhttp.la \
	parser/libparser.la \
	acl/libacls.la \
	acl/libapi.la \
	acl/libstate.la \
	anyp/libanyp.la \
	ip/libip.la \
	base/libbase.la \
	ipc/libipc.la \
	mem/libmem.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttpReply_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testHttpRequest
tests_testHttpRequest_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(DNSSOURCE) \
	$(HTCPSOURCE) \
	$(IPC_SOURCE) \
	$(SNMP_SOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AuthReg.h \
	BodyPipe.cc \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	CachePeer.cc \
	CachePeer.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	tests/stub_ETag.cc \
	tests/stub_EventLoop.cc \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	FwdState.cc \
	FwdState.h \
	HappyConnOpener.cc \
	HappyConnOpener.h \
	HttpBody.cc \
	HttpBody.h \
	tests/stub_HttpControlMsg.cc \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	HttpRequest.cc \
	tests/testHttpRequest.cc \
	tests/testHttpRequest.h \
	tests/testHttpRequestMethod.cc \
	tests/testHttpRequestMethod.h \
	tests/stub_HttpUpgradeProtocolAccess.cc \
	IoStats.h \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	PeerPoolMgr.cc \
	PeerPoolMgr.h \
	Pipeline.cc \
	Pipeline.h \
	RefreshPattern.h \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/stub_SBufDetailedStats.cc \
	SquidMath.cc \
	SquidMath.h \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	cache_manager.cc \
	tests/stub_carp.cc \
	carp.h \
	cbdata.cc \
	clientStream.cc \
	tests/stub_client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_request.cc \
	debug.cc \
	dlink.cc \
	dlink.h \
	errorpage.cc \
	event.cc \
	external_acl.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	fqdncache.cc \
	fqdncache.h \
	fs_io.cc \
	fs_io.h \
	tests/stub_gopher.cc \
	gopher.h \
	helper.cc \
	hier_code.h \
	http.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.cc \
	int.h \
	internal.cc \
	internal.h \
	tests/stub_ipc_Forwarder.cc \
	ipcache.cc \
	tests/stub_libauth.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libdiskio.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libstore.cc \
	tests/stub_main_cc.cc \
	mem_node.cc \
	mime.cc \
	mime.h \
	mime_header.cc \
	mime_header.h \
	multicast.cc \
	multicast.h \
	neighbors.cc \
	neighbors.h \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.cc \
	peer_proxy_negotiate_auth.h \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_sourcehash.h \
	peer_userhash.cc \
	peer_userhash.h \
	tests/stub_redirect.cc \
	redirect.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	stat.cc \
	stat.h \
	stmem.cc \
	store.cc \
	store_client.cc \
	tests/stub_store_digest.cc \
	store_digest.h \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	store_log.cc \
	store_log.h \
	store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapin.cc \
	store_swapin.h \
	store_swapmeta.cc \
	store_swapout.cc \
	time.cc \
	tools.cc \
	tools.h \
	tests/stub_tunnel.cc \
	urn.cc \
	urn.h \
	tests/stub_wccp2.cc \
	wccp2.h \
	tests/stub_whois.cc \
	whois.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testHttpRequest_SOURCES = \
	$(BUILT_SOURCES)
tests_testHttpRequest_LDADD = \
	libsquid.la \
	clients/libclients.la \
	servers/libservers.la \
	helper/libhelper.la \
	ftp/libftp.la \
	http/libhttp.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	parser/libparser.la \
	ip/libip.la \
	fs/libfs.la \
	$(SSL_LIBS) \
	ipc/libipc.la \
	proxyp/libproxyp.la \
	parser/libparser.la \
	dns/libdns.la \
	base/libbase.la \
	mgr/libmgr.la \
	anyp/libanyp.la \
	$(SNMP_LIBS) \
	icmp/libicmp.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	store/libstore.la \
	sbuf/libsbuf.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(LIBCPPUNIT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttpRequest_LDFLAGS = $(LIBADD_DL)

## Tests of ip/*

check_PROGRAMS += tests/testIpAddress
tests_testIpAddress_SOURCES = \
	tests/testIpAddress.cc \
	tests/testIpAddress.h
nodist_tests_testIpAddress_SOURCES = \
	tests/stub_SBuf.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_tools.cc
tests_testIpAddress_LDADD = \
	ip/libip.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testIpAddress_LDFLAGS = $(LIBADD_DL)

## Tests of icmp/*

check_PROGRAMS += tests/testIcmp
# icmp/libicmpcore.la is used by pinger so SHOULD NOT require more dependancies! :-(
tests_testIcmp_SOURCES = \
	tests/testIcmp.cc \
	tests/testIcmp.h
nodist_tests_testIcmp_SOURCES = \
	tests/stub_SBuf.cc \
	SquidTime.h \
	tests/stub_debug.cc \
	globals.cc \
	icmp/Icmp.h \
	tests/stub_libmem.cc \
	time.cc
tests_testIcmp_LDADD=\
	icmp/libicmpcore.la \
	ip/libip.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testIcmp_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testNetDb
tests_testNetDb_SOURCES = \
	tests/testNetDb.cc \
	tests/testNetDb.h
nodist_tests_testNetDb_SOURCES = \
	tests/stub_SBuf.cc \
	SquidTime.h \
	tests/stub_debug.cc \
	globals.cc \
	tests/stub_libmem.cc \
	time.cc
tests_testNetDb_LDADD = \
	icmp/libicmp.la \
	ip/libip.la \
	base/libbase.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testNetDb_LDFLAGS = $(LIBADD_DL)

## Tests of mgr/* and CacheManager objects

check_PROGRAMS += tests/testCacheManager
tests_testCacheManager_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(DNSSOURCE) \
	$(HTCPSOURCE) \
	$(IPC_SOURCE) \
	$(SNMP_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AuthReg.h \
	BodyPipe.cc \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	tests/testCacheManager.cc \
	tests/testCacheManager.h \
	CachePeer.cc \
	CachePeer.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	tests/stub_ETag.cc \
	tests/stub_EventLoop.cc \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	FileMap.h \
	FwdState.cc \
	FwdState.h \
	HappyConnOpener.cc \
	HappyConnOpener.h \
	HttpBody.cc \
	HttpBody.h \
	tests/stub_HttpControlMsg.cc \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	HttpRequest.cc \
	tests/stub_HttpUpgradeProtocolAccess.cc \
	IoStats.h \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	PeerPoolMgr.cc \
	PeerPoolMgr.h \
	Pipeline.cc \
	Pipeline.h \
	RefreshPattern.h \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/stub_SBufDetailedStats.cc \
	SquidMath.cc \
	SquidMath.h \
	StatCounters.cc \
	StatCounters.h \
	tests/stub_StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	cache_manager.cc \
	tests/stub_carp.cc \
	carp.h \
	cbdata.cc \
	clientStream.cc \
	tests/stub_client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_request.cc \
	debug.cc \
	dlink.cc \
	dlink.h \
	errorpage.cc \
	event.cc \
	external_acl.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	filemap.cc \
	fqdncache.cc \
	fqdncache.h \
	fs_io.cc \
	fs_io.h \
	tests/stub_gopher.cc \
	gopher.h \
	helper.cc \
	hier_code.h \
	http.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.cc \
	int.h \
	internal.cc \
	internal.h \
	tests/stub_ipc_Forwarder.cc \
	ipcache.cc \
	tests/stub_libauth.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libdiskio.cc \
	tests/stub_liberror.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libstore.cc \
	tests/stub_main_cc.cc \
	mem_node.cc \
	mime.cc \
	mime.h \
	mime_header.cc \
	mime_header.h \
	multicast.cc \
	multicast.h \
	neighbors.cc \
	neighbors.h \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.cc \
	peer_proxy_negotiate_auth.h \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_sourcehash.h \
	peer_userhash.cc \
	peer_userhash.h \
	tests/stub_redirect.cc \
	redirect.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	stat.cc \
	stat.h \
	stmem.cc \
	store.cc \
	store_client.cc \
	tests/stub_store_digest.cc \
	store_digest.h \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	store_log.cc \
	store_log.h \
	store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapin.cc \
	store_swapin.h \
	store_swapmeta.cc \
	store_swapout.cc \
	time.cc \
	tools.cc \
	tools.h \
	tests/stub_tunnel.cc \
	urn.cc \
	urn.h \
	tests/stub_wccp2.cc \
	wccp2.h \
	tests/stub_whois.cc \
	whois.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testCacheManager_SOURCES = \
	$(BUILT_SOURCES)
# comm.cc only requires comm/libcomm.la until fdc_table is dead.
tests_testCacheManager_LDADD = \
	libsquid.la \
	clients/libclients.la \
	servers/libservers.la \
	ftp/libftp.la \
	helper/libhelper.la \
	http/libhttp.la \
	proxyp/libproxyp.la \
	parser/libparser.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	dns/libdns.la \
	base/libbase.la \
	ip/libip.la \
	fs/libfs.la \
	comm/libcomm.la \
	eui/libeui.la \
	icmp/libicmp.la \
	log/liblog.la \
	format/libformat.la \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(SSL_LIBS) \
	anyp/libanyp.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	mem/libmem.la \
	store/libstore.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(LIBCPPUNIT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testCacheManager_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testStatHist
tests_testStatHist_SOURCES = \
	tests/stub_DelayId.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_MemBuf.cc \
	tests/stub_MemObject.cc \
	tests/stub_SBufDetailedStats.cc \
	StatHist.cc \
	tests/testStatHist.cc \
	StatHist.h \
	tests/testStatHist.h \
	String.cc \
	tests/stub_cache_manager.cc \
	tests/stub_cbdata.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_fatal.cc \
	fatal.h \
	tests/stub_libmem.cc \
	tests/stub_mime.cc \
	mime.h \
	tests/stub_pconn.cc \
	repl_modules.h \
	tests/stub_stmem.cc \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tests/stub_tools.cc \
	tools.h
nodist_tests_testStatHist_SOURCES = \
	$(TESTSOURCES)
tests_testStatHist_LDADD = \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB)
tests_testStatHist_LDFLAGS = $(LIBADD_DL)

## Tests of ConfigParser

check_PROGRAMS += tests/testConfigParser
tests_testConfigParser_SOURCES = \
	ClientInfo.h \
	ConfigParser.cc \
	tests/testConfigParser.cc \
	tests/testConfigParser.h \
	tests/stub_HelperChildConfig.cc \
	tests/stub_MemBuf.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_fatal.cc \
	fatal.h \
	tests/stub_libmem.cc \
	tests/stub_time.cc \
	tests/stub_tools.cc \
	tools.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testConfigParser_SOURCES = \
	$(TESTSOURCES)
tests_testConfigParser_LDADD = \
	libsquid.la \
	ip/libip.la \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testConfigParser_LDFLAGS = $(LIBADD_DL)

## Tests of Event handling

check_PROGRAMS += tests/testEvent
tests_testEvent_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(DNSSOURCE) \
	$(HTCPSOURCE) \
	$(IPC_SOURCE) \
	$(SNMP_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AuthReg.h \
	BodyPipe.cc \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	CachePeer.cc \
	CachePeer.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	tests/stub_ETag.cc \
	tests/testEvent.cc \
	tests/testEvent.h \
	EventLoop.cc \
	EventLoop.h \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	FileMap.h \
	FwdState.cc \
	FwdState.h \
	HappyConnOpener.cc \
	HappyConnOpener.h \
	HttpBody.cc \
	HttpBody.h \
	tests/stub_HttpControlMsg.cc \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	HttpRequest.cc \
	tests/stub_HttpUpgradeProtocolAccess.cc \
	IoStats.h \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	PeerPoolMgr.cc \
	PeerPoolMgr.h \
	Pipeline.cc \
	Pipeline.h \
	RefreshPattern.h \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/stub_SBufDetailedStats.cc \
	SquidMath.cc \
	SquidMath.h \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	cache_manager.cc \
	tests/stub_carp.cc \
	carp.h \
	cbdata.cc \
	clientStream.cc \
	tests/stub_client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_request.cc \
	debug.cc \
	dlink.cc \
	dlink.h \
	errorpage.cc \
	event.cc \
	external_acl.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	filemap.cc \
	fqdncache.cc \
	fqdncache.h \
	fs_io.cc \
	fs_io.h \
	tests/stub_gopher.cc \
	gopher.h \
	helper.cc \
	hier_code.h \
	http.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.cc \
	int.h \
	internal.cc \
	internal.h \
	tests/stub_ipc_Forwarder.cc \
	ipcache.cc \
	tests/stub_libauth.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libdiskio.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libstore.cc \
	tests/stub_main_cc.cc \
	mem_node.cc \
	mime.cc \
	mime.h \
	mime_header.cc \
	mime_header.h \
	multicast.cc \
	multicast.h \
	neighbors.cc \
	neighbors.h \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.cc \
	peer_proxy_negotiate_auth.h \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_sourcehash.h \
	peer_userhash.cc \
	peer_userhash.h \
	tests/stub_redirect.cc \
	redirect.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	stat.cc \
	stat.h \
	stmem.cc \
	store.cc \
	store_client.cc \
	tests/stub_store_digest.cc \
	store_digest.h \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	store_log.cc \
	store_log.h \
	store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapin.cc \
	store_swapin.h \
	store_swapmeta.cc \
	store_swapout.cc \
	tests/CapturingStoreEntry.h \
	time.cc \
	tools.cc \
	tools.h \
	tests/stub_tunnel.cc \
	urn.cc \
	urn.h \
	tests/stub_wccp2.cc \
	wccp2.h \
	tests/stub_whois.cc \
	whois.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testEvent_SOURCES = \
	$(BUILT_SOURCES)
tests_testEvent_LDADD = \
	libsquid.la \
	clients/libclients.la \
	servers/libservers.la \
	ftp/libftp.la \
	helper/libhelper.la \
	http/libhttp.la \
	proxyp/libproxyp.la \
	parser/libparser.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	dns/libdns.la \
	base/libbase.la \
	ip/libip.la \
	fs/libfs.la \
	anyp/libanyp.la \
	icmp/libicmp.la \
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
	ipc/libipc.la \
	mgr/libmgr.la \
	store/libstore.la \
	sbuf/libsbuf.la \
	$(SNMP_LIBS) \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(LIBCPPUNIT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEvent_LDFLAGS = $(LIBADD_DL)

check_PROGRAMS += tests/testEventLoop
tests_testEventLoop_SOURCES = \
	$(DELAY_POOL_SOURCE) \
	$(DNSSOURCE) \
	$(HTCPSOURCE) \
	$(IPC_SOURCE) \
	$(SNMP_SOURCE) \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	AccessLogEntry.cc \
	AuthReg.h \
	BodyPipe.cc \
	tests/stub_CacheDigest.cc \
	CacheDigest.h \
	CachePeer.cc \
	CachePeer.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	tests/stub_ETag.cc \
	EventLoop.cc \
	tests/testEventLoop.cc \
	EventLoop.h \
	tests/testEventLoop.h \
	ExternalACLEntry.cc \
	FadingCounter.cc \
	FileMap.h \
	FwdState.cc \
	FwdState.h \
	HappyConnOpener.cc \
	HappyConnOpener.h \
	HttpBody.cc \
	HttpBody.h \
	tests/stub_HttpControlMsg.cc \
	HttpHdrCc.cc \
	HttpHdrCc.h \
	HttpHdrContRange.cc \
	HttpHdrRange.cc \
	HttpHdrSc.cc \
	HttpHdrScTarget.cc \
	HttpHeader.cc \
	HttpHeader.h \
	HttpHeaderFieldInfo.h \
	HttpHeaderFieldStat.h \
	HttpHeaderTools.cc \
	HttpHeaderTools.h \
	HttpReply.cc \
	HttpRequest.cc \
	tests/stub_HttpUpgradeProtocolAccess.cc \
	IoStats.h \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	MemStore.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	PeerPoolMgr.cc \
	PeerPoolMgr.h \
	Pipeline.cc \
	Pipeline.h \
	RefreshPattern.h \
	RemovalPolicy.cc \
	RequestFlags.cc \
	RequestFlags.h \
	ResolvedPeers.cc \
	ResolvedPeers.h \
	tests/stub_SBufDetailedStats.cc \
	SquidMath.cc \
	SquidMath.h \
	StatCounters.cc \
	StatCounters.h \
	StatHist.cc \
	StatHist.h \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	StrList.cc \
	StrList.h \
	String.cc \
	Transients.cc \
	tests/stub_cache_cf.cc \
	cache_cf.h \
	cache_manager.cc \
	tests/stub_carp.cc \
	carp.h \
	cbdata.cc \
	clientStream.cc \
	tests/stub_client_db.cc \
	client_side.cc \
	client_side.h \
	client_side_reply.cc \
	client_side_request.cc \
	debug.cc \
	dlink.cc \
	dlink.h \
	errorpage.cc \
	event.cc \
	external_acl.cc \
	tests/stub_fatal.cc \
	fatal.h \
	fd.cc \
	fd.h \
	fde.cc \
	filemap.cc \
	fqdncache.cc \
	fqdncache.h \
	fs_io.cc \
	fs_io.h \
	tests/stub_gopher.cc \
	gopher.h \
	helper.cc \
	hier_code.h \
	http.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.cc \
	int.h \
	internal.cc \
	internal.h \
	tests/stub_ipc_Forwarder.cc \
	ipcache.cc \
	tests/stub_libauth.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libdiskio.cc \
	tests/stub_liberror.cc \
	tests/stub_libeui.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libstore.cc \
	tests/stub_main_cc.cc \
	mem_node.cc \
	mime.cc \
	mime.h \
	mime_header.cc \
	mime_header.h \
	multicast.cc \
	multicast.h \
	neighbors.cc \
	neighbors.h \
	pconn.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.cc \
	peer_proxy_negotiate_auth.h \
	peer_select.cc \
	peer_sourcehash.cc \
	peer_sourcehash.h \
	peer_userhash.cc \
	peer_userhash.h \
	tests/stub_redirect.cc \
	redirect.h \
	refresh.cc \
	refresh.h \
	repl_modules.h \
	stat.cc \
	stat.h \
	stmem.cc \
	store.cc \
	store_client.cc \
	tests/stub_store_digest.cc \
	store_digest.h \
	store_io.cc \
	store_key_md5.cc \
	store_key_md5.h \
	store_log.cc \
	store_log.h \
	store_rebuild.cc \
	store_rebuild.h \
	tests/stub_store_stats.cc \
	store_swapin.cc \
	store_swapin.h \
	store_swapmeta.cc \
	store_swapout.cc \
	time.cc \
	tools.cc \
	tools.h \
	tests/stub_tunnel.cc \
	urn.cc \
	urn.h \
	tests/stub_wccp2.cc \
	wccp2.h \
	tests/stub_whois.cc \
	whois.h \
	wordlist.cc \
	wordlist.h
nodist_tests_testEventLoop_SOURCES = \
	$(BUILT_SOURCES)
tests_testEventLoop_LDADD = \
	libsquid.la \
	clients/libclients.la \
	servers/libservers.la \
	ftp/libftp.la \
	helper/libhelper.la \
	http/libhttp.la \
	proxyp/libproxyp.la \
	parser/libparser.la \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	dns/libdns.la \
	base/libbase.la \
	ip/libip.la \
	fs/libfs.la \
	anyp/libanyp.la \
	icmp/libicmp.la \
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
	ipc/libipc.la \
	mgr/libmgr.la \
	sbuf/libsbuf.la \
	store/libstore.la \
	$(SNMP_LIBS) \
	$(NETTLELIB) \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(LIBCPPUNIT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEventLoop_LDFLAGS = $(LIBADD_DL)

## Run the unit tests. check_PROGRAMS only builds the binaries.
TESTS += $(check_PROGRAMS) testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/*.h $(srcdir)/DiskIO/*.h $(srcdir)/DiskIO/*/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1
## src/repl/ has no .h files and its own makefile.

CLEANFILES += testHeaders
.PHONY: testHeaders

