## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
	LoadableModule.h \
	LoadableModule.cc \
	LoadableModules.h \
	LoadableModules.cc

SUBDIRS	= mem base anyp helper dns ftp parser comm eui acl format clients sbuf servers fs repl store DiskIO
DIST_SUBDIRS = mem base anyp helper dns ftp parser comm eui acl format clients sbuf servers fs repl store DiskIO

if ENABLE_AUTH
SUBDIRS += auth
AUTH_LIBS= auth/libauth.la
AUTH_ACL_LIBS= auth/libacls.la
check_PROGRAMS+= tests/testACLMaxUserIP
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
	tests/testUfs \
	tests/testRock \
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


ACL_REGISTRATION_SOURCES = AclRegs.cc AuthReg.cc

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
	RefreshPattern.h \
	cache_cf.cc \
	CacheDigest.h \
	CacheDigest.cc \
	cache_manager.cc \
	NeighborTypeDomainList.h \
	CachePeer.cc \
	CachePeer.h \
	CacheManager.h \
	carp.h \
	carp.cc \
	cbdata.cc \
	cbdata.h \
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
	clientStreamForward.h \
	CollapsedForwarding.cc \
	CollapsedForwarding.h \
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
	fs_io.h \
	fs_io.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	Downloader.cc \
	Downloader.h \
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
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	Generic.h \
	globals.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	helper.h \
	hier_code.h \
	HierarchyLogEntry.h \
	$(HTCPSOURCE) \
	http.cc \
	http.h \
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
	HttpControlMsg.cc \
	HttpControlMsg.h \
	HttpMsg.cc \
	HttpMsg.h \
	HttpReply.cc \
	HttpReply.h \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	HttpRequest.h \
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
	LogTags.cc \
	LogTags.h \
	lookup_t.h \
	main.cc \
	MasterXaction.cc \
	MasterXaction.h \
	mem_node.cc \
	mem_node.h \
	MemBuf.cc \
	MemObject.cc \
	MemObject.h \
	MessageSizes.h \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Notes.h \
	Notes.cc \
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
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	PeerSelectState.h \
	PingData.h \
	Pipeline.cc \
	Pipeline.h \
	protos.h \
	redirect.h \
	redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	RemovalPolicy.h \
	send-announce.h \
	send-announce.cc \
	SBufStatsAction.h \
	SBufStatsAction.cc \
	sbuf/StringConvert.h \
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
	store_io.cc \
	StoreIOBuffer.h \
	StoreIOState.cc \
	StoreIOState.h \
	store_client.cc \
	StoreClient.h \
	store_digest.h \
	store_digest.cc \
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
	StoreMetaUnpacker.cc \
	StoreMetaUnpacker.h \
	$(STOREMETA_SOURCE) \
	StoreSearch.h \
	StoreStats.cc \
	StoreStats.h \
	StoreSwapLogData.cc \
	StoreSwapLogData.h \
	swap_log_op.h \
	Transients.cc \
	Transients.h \
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
	$(all_AUTHMODULES) \
	ConfigOption.h \
	$(DELAY_POOL_ALL_SOURCE) \
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
	MemBuf.h \
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
	ipc/libipc.la \
	mgr/libmgr.la \
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
	$(ATOMICLIB) \
	$(SSLLIB) \
	$(EPOLL_LIBS) \
	$(MINGW_LIBS) \
	$(KRB5LIBS) \
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
	ClientInfo.h \
	cbdata.h \
	cbdata.cc \
	debug.cc \
	int.h \
	int.cc \
	mem/forward.h \
	MemBuf.cc \
	MemBuf.h \
	Parsing.h \
	store_key_md5.h \
	store_key_md5.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	String.cc \
	SquidNew.cc \
	tests/stub_time.cc \
	ufsdump.cc \
	dlink.h \
	dlink.cc \
	helper/ChildConfig.h \
	tests/stub_HelperChildConfig.cc \
	RemovalPolicy.cc \
	$(WIN32_SOURCE) \
	fd.h \
	tests/stub_fd.cc
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

include $(srcdir)/tests/Stub.list

EXTRA_DIST = \
	cf_gen_defines \
	cf.data.pre \
	cf.data.depend \
	cf.data.sed \
	mk-globals-c.awk \
	mk-string-arrays.awk \
	repl_modules.sh \
	$(STUB_SOURCE) \
	mib.txt \
	mime.conf.default

# Make location configure settings available to the code
DEFS += -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\" -DDEFAULT_SQUID_DATA_DIR=\"$(datadir)\" -DDEFAULT_SQUID_CONFIG_DIR=\"$(sysconfdir)\"

snmp_core.o snmp_agent.o: ../lib/snmplib/libsnmplib.la $(top_srcdir)/include/cache_snmp.h

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


## FIXME: generate a sed command file from configure. Then this doesn't
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

check_PROGRAMS+=\
	tests/testBoilerplate \
	tests/testCacheManager \
	tests/testCharacterSet \
	tests/testDiskIO \
	tests/testDns \
	tests/testEnumIterator \
	tests/testEvent \
	tests/testEventLoop \
	tests/test_http_range \
	tests/testTokenizer \
	tests/testHttp1Parser \
	tests/testHttpReply \
	tests/testHttpRequest \
	tests/testIcmp \
	tests/testIpAddress \
	tests/testNetDb \
	tests/testStore \
	tests/testString \
	tests/testURL \
	tests/testSBuf \
	tests/testSBufList \
	tests/testConfigParser \
	tests/testStatHist \
	tests/testLookupTable \
	tests/testYesNoNone

if ENABLE_FS_ROCK
check_PROGRAMS += tests/testRock
endif
if ENABLE_FS_UFS
check_PROGRAMS += tests/testUfs
endif

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
#	X.h \
#	X.cc
#nodist_tests_testX_SOURCES=\
#   tests/stubs_as_needed.cc\
#	$(TESTSOURCES)
#tests_testX_LDFLAGS = $(LIBADD_DL)
#tests_testX_LDADD=\
#	$(LIBCPPUNIT_LIBS) \
#	$(COMPAT_LIB) \
#	$(XTRA_LIBS)

# - add other component .(h|cc) files needed to link and run tests
tests_testHttpReply_SOURCES=\
	cbdata.cc \
	cbdata.h \
	ConfigParser.cc \
	tests/stub_ETag.cc \
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
	HttpControlMsg.cc \
	HttpControlMsg.h \
	HttpMsg.cc \
	HttpMsg.h \
	HttpReply.cc \
	HttpReply.h \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemBuf.h \
	mime_header.h \
	mime_header.cc \
	Notes.h \
	Notes.cc \
	SquidString.h \
	SquidTime.h \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	tests/stub_event.cc \
	tests/stub_fd.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_libformat.cc \
	tests/stub_libauth.cc \
	tests/stub_libcomm.cc \
	tests/stub_libmgr.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libsslsquid.cc \
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
	tests/stub_time.cc \
	url.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testHttpReply_SOURCES=\
	$(TESTSOURCES)
tests_testHttpReply_LDFLAGS = $(LIBADD_DL)
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

tests_testACLMaxUserIP_SOURCES= \
	cbdata.cc \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	tests/stub_ETag.cc \
	event.cc \
	fatal.h \
	tests/stub_fatal.cc \
	FileMap.h \
	filemap.cc \
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
	int.h \
	int.cc \
	MasterXaction.cc \
	MasterXaction.h \
	Notes.cc \
	Notes.h \
	mem_node.cc \
	Parsing.cc \
	tests/stub_libsecurity.cc \
	SquidMath.cc \
	StatCounters.cc \
	StatCounters.h \
	StatHist.h \
	StrList.h \
	StrList.cc \
	tests/stub_StatHist.cc \
	stmem.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	store_key_md5.h \
	store_key_md5.cc \
	swap_log_op.cc \
	swap_log_op.h \
	tests/stub_SwapDir.cc \
	Transients.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	tests/stub_client_side.cc \
	tests/stub_debug.cc \
	tests/stub_DelayId.cc \
	tests/stub_errorpage.cc \
	fd.h \
	tests/stub_fd.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_HttpReply.cc \
	tests/stub_ipc_TypedMsgHdr.cc \
	tests/stub_libauth.cc \
	tests/stub_libcomm.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libformat.cc \
	tests/stub_libmem.cc \
	tests/stub_libsslsquid.cc \
	tests/stub_MemObject.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_pconn.cc \
	tests/stub_Port.cc \
	repl_modules.h \
	tests/stub_store.cc \
	tests/stub_store_client.cc \
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
	tests/stub_time.cc \
	url.cc \
	URL.h \
	MemBuf.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testACLMaxUserIP_SOURCES= \
	$(TESTSOURCES)
tests_testACLMaxUserIP_LDADD= \
	libsquid.la \
	helper/libhelper.la \
	http/libhttp.la \
	parser/libparser.la \
	$(AUTH_ACL_LIBS) \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	acl/libapi.la \
	anyp/libanyp.la \
	base/libbase.la \
	ip/libip.la \
	ipc/libipc.la \
	mgr/libmgr.la \
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
tests_testACLMaxUserIP_LDFLAGS = $(LIBADD_DL)

## a demonstration test that does nothing but shows the salient points
## involved in writing tests.
tests_testBoilerplate_SOURCES = \
	tests/testBoilerplate.cc \
	tests/testBoilerplate.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_time.cc
nodist_tests_testBoilerplate_SOURCES = \
	tests/stub_cbdata.cc \
	tests/stub_MemBuf.cc \
	$(TESTSOURCES)
tests_testBoilerplate_LDADD= \
	$(SSLLIB) \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testBoilerplate_LDFLAGS = $(LIBADD_DL)

## Tests of base/libbase.la objects
tests_testCharacterSet_SOURCES = \
	tests/testCharacterSet.cc \
	tests/testCharacterSet.h
nodist_tests_testCharacterSet_SOURCES = \
	base/CharacterSet.h \
	$(TESTSOURCES) \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_MemBuf.cc
tests_testCharacterSet_LDFLAGS = $(LIBADD_DL)
tests_testCharacterSet_LDADD= \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

## Tests of the CacheManager module.
tests_testCacheManager_SOURCES = \
	AccessLogEntry.cc \
	debug.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	String.cc \
	tests/testCacheManager.cc \
	tests/testCacheManager.h \
	tests/stub_main_cc.cc \
	tests/stub_HttpControlMsg.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	tests/stub_EventLoop.cc \
	time.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.h \
	AuthReg.h \
	RefreshPattern.h \
	cache_cf.cc \
	CachePeer.cc \
	CachePeer.h \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	carp.h \
	tests/stub_carp.cc \
	cbdata.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	tests/stub_ETag.cc \
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
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	gopher.h \
	gopher.cc \
	hier_code.h \
	helper.cc \
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
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	LogTags.cc \
	tests/stub_libsecurity.cc \
	MasterXaction.cc \
	MasterXaction.h \
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
	Notes.cc \
	Notes.h \
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
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	Pipeline.cc \
	Pipeline.h \
	redirect.h \
	tests/stub_redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	tests/stub_SBufDetailedStats.cc \
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
	tests/stub_libauth_acls.cc \
	tests/stub_libauth.cc \
	tests/stub_libdiskio.cc \
	tests/stub_StatHist.cc \
	stmem.cc \
	repl_modules.h \
	store.cc \
	store_client.cc \
	store_digest.h \
	tests/stub_store_digest.cc \
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
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	tools.h \
	tools.cc \
	Transients.cc \
	tests/stub_tunnel.cc \
	tests/stub_SwapDir.cc \
	MemStore.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	tests/stub_wccp2.cc \
	whois.h \
	tests/stub_whois.cc \
	FadingCounter.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
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
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testCacheManager_LDFLAGS = $(LIBADD_DL)

tests_testDiskIO_SOURCES = \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	cbdata.cc \
	client_db.h \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	FadingCounter.cc \
	fs_io.h \
	fs_io.cc \
	tests/stub_ETag.cc \
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
	int.h \
	int.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	mem_node.cc \
	Notes.h \
	Notes.cc \
	Parsing.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	RequestFlags.h \
	RequestFlags.cc \
	tests/stub_libsecurity.cc \
	StatCounters.h \
	StatCounters.cc \
	StatHist.h \
	tests/stub_StatHist.cc \
	stmem.cc \
	tests/stub_SBufDetailedStats.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
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
	tests/stub_SwapDir.cc \
	Transients.cc \
	log/access_log.h \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	cache_cf.h \
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
	tests/stub_libauth_acls.cc \
	tests/stub_libauth.cc \
	tests/stub_libeui.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_liblog.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_neighbors.cc \
	tests/stub_pconn.cc \
	tests/stub_Port.cc \
	tests/stub_stat.cc \
	tests/stub_store_client.cc \
	tests/stub_store_stats.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_UdsOp.cc \
	tests/testDiskIO.cc \
	tests/testDiskIO.h \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	tests/stub_time.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc \
	tools.h \
	tests/stub_tools.cc
nodist_tests_testDiskIO_SOURCES= \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
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
tests_testDiskIO_DEPENDENCIES = \
	DiskIO/libdiskio.la \
	$(SWAP_TEST_DS)

tests_testDns_SOURCES= \
	tests/testRFC1035.cc \
	tests/testRFC1035.h
nodist_tests_testDns_SOURCES= \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_SBuf.cc \
	tests/stub_tools.cc
tests_testDns_LDADD= \
	dns/libdns.la \
	base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testDns_LDFLAGS= $(LIBADD_DL)

tests_testEvent_SOURCES = \
	AccessLogEntry.cc \
	BodyPipe.cc \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	cache_cf.h \
	AuthReg.h \
	RefreshPattern.h \
	cache_cf.cc \
	CachePeer.cc \
	CachePeer.h \
	cache_manager.cc \
	carp.h \
	tests/stub_carp.cc \
	cbdata.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	tests/stub_ETag.cc \
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
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpControlMsg.cc \
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
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	LogTags.cc \
	tests/stub_libsecurity.cc \
	MasterXaction.cc \
	MasterXaction.h \
	tests/stub_libmem.cc \
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
	Notes.cc \
	Notes.h \
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
	Pipeline.cc \
	Pipeline.h \
	redirect.h \
	tests/stub_redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	StrList.h \
	StrList.cc \
	tests/stub_SBufDetailedStats.cc \
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
	tests/stub_store_digest.cc \
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
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	String.cc \
	tests/stub_SwapDir.cc \
	tests/CapturingStoreEntry.h \
	tests/testEvent.cc \
	tests/testEvent.h \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libauth.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libeui.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tools.h \
	tools.cc \
	Transients.cc \
	tests/stub_tunnel.cc \
	MemStore.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	tests/stub_wccp2.cc \
	whois.h \
	tests/stub_whois.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testEvent_SOURCES = \
	$(BUILT_SOURCES)
tests_testEvent_LDADD = \
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
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEvent_LDFLAGS = $(LIBADD_DL)

## Tests of the EventLoop module.
tests_testEventLoop_SOURCES = \
	AccessLogEntry.cc \
	BodyPipe.cc \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	cache_manager.cc \
	cache_cf.h \
	AuthReg.h \
	RefreshPattern.h \
	cache_cf.cc \
	CachePeer.cc \
	CachePeer.h \
	carp.h \
	tests/stub_carp.cc \
	cbdata.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	tests/stub_ETag.cc \
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
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpControlMsg.cc \
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
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	tests/stub_libmem.cc \
	mem_node.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Notes.cc \
	Notes.h \
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
	Pipeline.cc \
	Pipeline.h \
	RemovalPolicy.cc \
	redirect.h \
	tests/stub_redirect.cc \
	refresh.h \
	refresh.cc \
	tests/stub_SBufDetailedStats.cc \
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
	tests/stub_store_digest.cc \
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
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	tests/stub_SwapDir.cc \
	tests/testEventLoop.cc \
	tests/testEventLoop.h \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libauth.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libeui.cc \
	tests/stub_libsecurity.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tools.h \
	tools.cc \
	Transients.cc \
	tests/stub_tunnel.cc \
	MemStore.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	tests/stub_wccp2.cc \
	whois.h \
	tests/stub_whois.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testEventLoop_SOURCES = \
	$(BUILT_SOURCES)
tests_testEventLoop_LDADD = \
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
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testEventLoop_LDFLAGS = $(LIBADD_DL)

tests_test_http_range_SOURCES = \
	AccessLogEntry.cc \
	BodyPipe.cc \
	cache_cf.h \
	AuthReg.h \
	RefreshPattern.h \
	cache_cf.cc \
	CachePeer.cc \
	CachePeer.h \
	cache_manager.cc \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	carp.h \
	tests/stub_carp.cc \
	cbdata.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	debug.cc \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	tests/stub_ETag.cc \
	event.cc \
	FadingCounter.cc \
	fatal.h \
	tests/stub_libauth.cc \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	FileMap.h \
	filemap.cc \
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpControlMsg.cc \
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
	HttpReply.cc \
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	icp_v2.cc \
	icp_v3.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	tests/stub_libmem.cc \
	mem_node.cc \
	mime.h \
	mime.cc \
	mime_header.h \
	mime_header.cc \
	multicast.h \
	multicast.cc \
	neighbors.h \
	neighbors.cc \
	Notes.cc \
	Notes.h \
	Parsing.cc \
	peer_digest.cc \
	peer_proxy_negotiate_auth.h \
	peer_proxy_negotiate_auth.cc \
	peer_select.cc \
	peer_sourcehash.h \
	peer_sourcehash.cc \
	peer_userhash.h \
	peer_userhash.cc \
	Pipeline.cc \
	Pipeline.h \
	pconn.cc \
	redirect.h \
	tests/stub_redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	tests/stub_SBufDetailedStats.cc \
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
	tests/stub_store_digest.cc \
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
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	tests/stub_SwapDir.cc \
	Transients.cc \
	tests/test_http_range.cc \
	tests/stub_external_acl.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libeui.cc \
	tests/stub_libsecurity.cc \
	tests/stub_main_cc.cc \
	tests/stub_MemStore.cc \
	tests/stub_store_stats.cc \
	tests/stub_EventLoop.cc \
	time.cc \
	tools.h \
	tools.cc \
	tests/stub_tunnel.cc \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	tests/stub_wccp2.cc \
	whois.h \
	tests/stub_whois.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
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
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_test_http_range_LDFLAGS = $(LIBADD_DL)

## Tests of parser/* objects
tests_testTokenizer_SOURCES = \
	tests/testTokenizer.h \
	tests/testTokenizer.cc
nodist_tests_testTokenizer_SOURCES = \
	parser/Tokenizer.h \
	SquidString.h \
	String.cc \
	$(TESTSOURCES) \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_time.cc \
	tests/stub_SBufDetailedStats.cc
tests_testTokenizer_LDFLAGS = $(LIBADD_DL)
tests_testTokenizer_LDADD = \
	parser/libparser.la \
	base/libbase.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testHttp1Parser_SOURCES = \
	Debug.h \
	MemBuf.cc \
	MemBuf.h \
	tests/stub_MemObject.cc \
	mime_header.cc \
	mime_header.h \
	String.cc \
	cache_cf.h \
	tests/stub_SBufDetailedStats.cc \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_comm.cc \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_event.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	tests/stub_stmem.cc \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/testHttp1Parser.cc \
	tests/testHttp1Parser.h \
	tests/stub_time.cc \
	wordlist.h \
	wordlist.cc
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

## Tests of the HttpRequest module.
tests_testHttpRequest_SOURCES = \
	AccessLogEntry.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	tests/stub_libmem.cc \
	String.cc \
	tests/testHttpRequest.h \
	tests/testHttpRequest.cc \
	tests/testHttpRequestMethod.h \
	tests/testHttpRequestMethod.cc \
	tests/stub_libauth.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libeui.cc \
	tests/stub_store_stats.cc \
	tests/stub_EventLoop.cc \
	time.cc \
	BodyPipe.cc \
	cache_manager.cc \
	cache_cf.h \
	AuthReg.h \
	RefreshPattern.h \
	cache_cf.cc \
	debug.cc \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	CachePeer.cc \
	CachePeer.h \
	carp.h \
	tests/stub_carp.cc \
	cbdata.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
	dlink.h \
	dlink.cc \
	$(DNSSOURCE) \
	errorpage.cc \
	tests/stub_ETag.cc \
	external_acl.cc \
	ExternalACLEntry.cc \
	fatal.h \
	tests/stub_fatal.cc \
	fd.h \
	fd.cc \
	fde.cc \
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpControlMsg.cc \
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
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	LogTags.cc \
	tests/stub_libsecurity.cc \
	MasterXaction.cc \
	MasterXaction.h \
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
	Notes.cc \
	Notes.h \
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
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	Pipeline.cc \
	Pipeline.h \
	redirect.h \
	tests/stub_libauth_acls.cc \
	tests/stub_redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	tests/stub_SBufDetailedStats.cc \
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
	tests/stub_store_digest.cc \
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
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	StrList.h \
	StrList.cc \
	event.cc \
	tools.h \
	tools.cc \
	Transients.cc \
	tests/stub_tunnel.cc \
	tests/stub_SwapDir.cc \
	MemStore.cc \
	url.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	tests/stub_wccp2.cc \
	whois.h \
	tests/stub_whois.cc \
	FadingCounter.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
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
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testHttpRequest_LDFLAGS = $(LIBADD_DL)

## Tests for icmp/* objects
# icmp/libicmpcore.la is used by pinger so SHOULD NOT require more dependancies! :-(
tests_testIcmp_SOURCES = \
	tests/testIcmp.h \
	tests/testIcmp.cc
nodist_tests_testIcmp_SOURCES = \
	icmp/Icmp.h \
	SquidTime.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	time.cc \
	globals.cc
tests_testIcmp_LDFLAGS = $(LIBADD_DL)
tests_testIcmp_LDADD=\
	icmp/libicmpcore.la \
	ip/libip.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testNetDb_SOURCES = \
	tests/testNetDb.cc \
	tests/testNetDb.h
nodist_tests_testNetDb_SOURCES = \
	SquidTime.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	time.cc \
	globals.cc
tests_testNetDb_LDFLAGS = $(LIBADD_DL)
tests_testNetDb_LDADD = \
	icmp/libicmp.la \
	ip/libip.la \
	base/libbase.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

## Tests for ip/* objects
tests_testIpAddress_SOURCES= \
	tests/testAddress.cc \
	tests/testAddress.h
nodist_tests_testIpAddress_SOURCES= \
	ip/Address.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_tools.cc
tests_testIpAddress_LDADD= \
	ip/libip.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testIpAddress_LDFLAGS= $(LIBADD_DL)

## why so many sources? well httpHeaderTools requites ACLChecklist & friends.
## first line - what we are testing.
tests_testStore_SOURCES= \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	cbdata.cc \
	ClientInfo.h \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
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
	RequestFlags.cc \
	RequestFlags.h \
	int.h \
	int.cc \
	MasterXaction.cc \
	MasterXaction.h \
	mem_node.cc \
	MemBuf.cc \
	MemObject.cc \
	Notes.h \
	Notes.cc \
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
	store_io.cc \
	store_swapout.cc \
	StoreIOState.cc \
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	store_key_md5.h \
	store_key_md5.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	tests/CapturingStoreEntry.h \
	log/access_log.h \
	tests/stub_access_log.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_client_side_request.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	fd.h \
	fde.h \
	tests/stub_fd.cc \
	tests/stub_helper.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_http.cc \
	tests/stub_libauth.cc \
	tests/stub_libeui.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libformat.cc \
	tests/stub_libsecurity.cc \
	tests/stub_libsslsquid.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpReply.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_libcomm.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_Port.cc \
	tests/stub_stat.cc \
	tests/stub_store_client.cc \
	tests/stub_store_stats.cc \
	store_rebuild.h \
	tests/stub_store_rebuild.cc \
	tests/stub_store_swapout.cc \
	tools.h \
	Transients.cc \
	tests/stub_tools.cc \
	tests/stub_UdsOp.cc \
	tests/testPackableStream.cc \
	tests/testPackableStream.h \
	tests/testStore.cc \
	tests/testStore.h \
	tests/testStoreController.cc \
	tests/testStoreController.h \
	tests/testStoreHashIndex.cc \
	tests/testStoreHashIndex.h \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	tests/TestSwapDir.cc \
	tests/TestSwapDir.h \
	tests/stub_time.cc \
	url.cc \
	wordlist.h \
	wordlist.cc

nodist_tests_testStore_SOURCES= \
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

## string needs mem.cc.
## mem.cc needs ClientInfo.h
## libsquid pulls in SquidConfig and children. stub them.
tests_testString_SOURCES = \
	ClientInfo.h \
	MemBuf.cc \
	String.cc \
	tests/stub_SBufDetailedStats.cc \
	tests/testString.cc \
	tests/testString.h \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	tests/stub_cache_manager.cc \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_libmem.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/stub_time.cc \
	wordlist.h \
	wordlist.cc
nodist_tests_testString_SOURCES = \
	$(TESTSOURCES)
tests_testString_LDADD = \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	sbuf/libsbuf.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(REGEXLIB) \
	$(SSLLIB) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testString_LDFLAGS = $(LIBADD_DL)

SWAP_TEST_DS =\
	repl_modules.o \
	ident/libident.la \
	acl/libacls.la \
	acl/libstate.la \
	acl/libapi.la \
	base/libbase.la \
	libsquid.la \
	ip/libip.la \
	fs/libfs.la \
	DiskIO/libdiskio.la \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(REPL_OBJS)

tests_testUfs_SOURCES = \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	tests/testUfs.cc \
	tests/testUfs.h \
	tests/stub_cache_manager.cc \
	tests/stub_client_db.cc \
	tests/stub_CollapsedForwarding.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_icp.cc \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libeui.cc \
	tests/stub_libicmp.cc \
	tests/stub_liblog.cc \
	tests/stub_MemStore.cc \
	tests/stub_neighbors.cc \
	tests/stub_pconn.cc \
	tests/stub_Port.cc \
	tests/stub_UdsOp.cc \
	internal.h \
	tests/stub_internal.cc \
	tests/stub_libformat.cc \
	tests/stub_libsecurity.cc \
	tests/stub_stat.cc \
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
	FadingCounter.cc \
	fs_io.h \
	fs_io.cc \
	FileMap.h \
	filemap.cc \
	HttpBody.h \
	HttpBody.cc \
	HttpReply.cc \
	int.h \
	int.cc \
	RequestFlags.h \
	RequestFlags.cc \
	Transients.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemObject.cc \
	Notes.h \
	Notes.cc \
	StoreSwapLogData.cc \
	StoreIOState.cc \
	StoreMetaUnpacker.cc \
	$(STOREMETA_SOURCE) \
	StoreFileSystem.cc \
	store_io.cc \
	store_swapout.cc \
	store_swapmeta.cc \
	$(UNLINKDSOURCE) \
	$(WIN32_SOURCE) \
	event.cc \
	$(DELAY_POOL_SOURCE) \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	ConfigParser.cc \
	EventLoop.cc \
	HttpMsg.cc \
	RemovalPolicy.cc \
	repl_modules.h \
	store.cc \
	store_key_md5.h \
	store_key_md5.cc \
	Parsing.cc \
	ConfigOption.cc \
	tests/stub_acl.cc \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	tests/stub_helper.cc \
	cbdata.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	tests/stub_debug.cc \
	tests/stub_client_side_request.cc \
	tests/stub_http.cc \
	tests/stub_libauth.cc \
	mem_node.cc \
	stmem.cc \
	mime.h \
	tests/stub_mime.cc \
	HttpHeaderFieldInfo.h \
	HttpHeaderTools.h \
	HttpHeaderTools.cc \
	HttpHeader.h \
	HttpHeader.cc \
	ClientInfo.h \
	MemBuf.cc \
	HttpHdrContRange.cc \
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
	wordlist.h \
	wordlist.cc

nodist_tests_testUfs_SOURCES = \
	$(TESTSOURCES) \
	SquidMath.cc \
	SquidMath.h \
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
	$(SSL_LIBS) \
	ipc/libipc.la \
	comm/libcomm.la \
	anyp/libanyp.la \
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
tests_testUfs_DEPENDENCIES = \
	$(SWAP_TEST_DS)

check_PROGRAMS += testRefCount
testRefCount_SOURCES= \
	base/Lock.h \
	base/RefCount.h \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_MemBuf.cc \
	tests/testRefCount.cc
testRefCount_LDADD = \
	base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testRock_SOURCES = \
	AccessLogEntry.cc \
	AccessLogEntry.h \
	cbdata.cc \
	CacheDigest.h \
	CollapsedForwarding.h \
	CollapsedForwarding.cc \
	tests/stub_CacheDigest.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	fs_io.h \
	fs_io.cc \
	ETag.cc \
	EventLoop.cc \
	event.cc \
	FadingCounter.cc \
	fatal.h \
	fatal.cc \
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
	int.h \
	int.cc \
	MasterXaction.cc \
	MasterXaction.h \
	MemBuf.cc \
	MemObject.cc \
	mem_node.cc \
	Notes.h \
	Notes.cc \
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
	tests/stub_stat.cc \
	store.cc \
	StoreFileSystem.cc \
	StoreIOState.cc \
	StoreMetaUnpacker.cc \
	$(STOREMETA_SOURCE) \
	StoreSwapLogData.cc \
	store_io.cc \
	store_key_md5.h \
	store_key_md5.cc \
	store_swapmeta.cc \
	store_swapout.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	Transients.h \
	Transients.cc \
	tests/testRock.cc \
	tests/testRock.h \
	tests/testStoreSupport.cc \
	tests/testStoreSupport.h \
	log/access_log.h \
	tests/stub_access_log.cc \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	client_db.h \
	tests/stub_cache_manager.cc \
	tests/stub_client_db.cc \
	tests/stub_client_side_request.cc \
	tests/stub_debug.cc \
	tests/stub_errorpage.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_http.cc \
	tests/stub_HttpRequest.cc \
	tests/stub_libauth.cc \
	tests/stub_icp.cc \
	tests/stub_ipc.cc \
	tests/stub_ipcache.cc \
	tests/stub_libeui.cc \
	tests/stub_libformat.cc \
	tests/stub_libicmp.cc \
	tests/stub_liblog.cc \
	tests/stub_libmgr.cc \
	tests/stub_libsecurity.cc \
	tests/stub_MemStore.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_neighbors.cc \
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
	wordlist.h \
	wordlist.cc \
	$(DELAY_POOL_SOURCE) \
	$(UNLINKDSOURCE)
nodist_tests_testRock_SOURCES = \
	swap_log_op.cc \
	SquidMath.cc \
	SquidMath.h \
	$(TESTSOURCES)
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
tests_testRock_DEPENDENCIES = \
	$(SWAP_TEST_DS)

## Tests of the URL module.
## TODO: Trim this down once the insanity is over.
tests_testURL_SOURCES = \
	AccessLogEntry.cc \
	BodyPipe.cc \
	cache_cf.h \
	AuthReg.h \
	RefreshPattern.h \
	cache_cf.cc \
	tests/stub_cache_manager.cc \
	CacheDigest.h \
	tests/stub_CacheDigest.cc \
	CachePeer.cc \
	CachePeer.h \
	carp.h \
	tests/stub_carp.cc \
	cbdata.cc \
	client_db.h \
	client_db.cc \
	client_side.h \
	client_side.cc \
	client_side_reply.cc \
	client_side_request.cc \
	ClientInfo.h \
	clientStream.cc \
	tests/stub_CollapsedForwarding.cc \
	ConfigOption.cc \
	ConfigParser.cc \
	CpuAffinityMap.cc \
	CpuAffinityMap.h \
	CpuAffinitySet.cc \
	CpuAffinitySet.h \
	$(DELAY_POOL_SOURCE) \
	fs_io.h \
	fs_io.cc \
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
	fqdncache.h \
	fqdncache.cc \
	FwdState.cc \
	FwdState.h \
	gopher.h \
	gopher.cc \
	helper.cc \
	hier_code.h \
	$(HTCPSOURCE) \
	http.cc \
	HttpBody.h \
	HttpBody.cc \
	tests/stub_HttpControlMsg.cc \
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
	HttpReply.cc \
	PeerPoolMgr.h \
	PeerPoolMgr.cc \
	RequestFlags.h \
	RequestFlags.cc \
	HttpRequest.cc \
	icp_v2.cc \
	icp_v3.cc \
	$(IPC_SOURCE) \
	ipcache.cc \
	int.h \
	int.cc \
	internal.h \
	internal.cc \
	tests/stub_libeui.cc \
	LogTags.cc \
	MasterXaction.cc \
	MasterXaction.h \
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
	Notes.h \
	Notes.cc \
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
	Pipeline.cc \
	Pipeline.h \
	redirect.h \
	tests/stub_redirect.cc \
	refresh.h \
	refresh.cc \
	RemovalPolicy.cc \
	tests/stub_SBufDetailedStats.cc \
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
	tests/stub_store_digest.cc \
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
	tests/stub_StoreMeta.cc \
	StoreMetaUnpacker.cc \
	StoreSwapLogData.cc \
	String.cc \
	StrList.h \
	StrList.cc \
	Transients.cc \
	tests/stub_SwapDir.cc \
	MemStore.cc \
	tests/stub_debug.cc \
	tests/stub_libauth_acls.cc \
	tests/stub_libauth.cc \
	tests/stub_libdiskio.cc \
	tests/stub_libmem.cc \
	tests/stub_libsecurity.cc \
	tests/stub_main_cc.cc \
	tests/stub_ipc_Forwarder.cc \
	tests/stub_store_stats.cc \
	tests/testURL.cc \
	tests/testURL.h \
	tests/testUriScheme.cc \
	tests/testUriScheme.h \
	tests/stub_time.cc \
	tests/stub_EventLoop.cc \
	tools.h \
	tools.cc \
	tests/stub_tunnel.cc \
	url.cc \
	urn.h \
	urn.cc \
	wccp2.h \
	tests/stub_wccp2.cc \
	whois.h \
	tests/stub_whois.cc \
	FadingCounter.cc \
	$(WIN32_SOURCE) \
	wordlist.h \
	wordlist.cc
nodist_tests_testURL_SOURCES = \
	$(BUILT_SOURCES)
tests_testURL_LDADD = \
	libsquid.la \
	clients/libclients.la \
	servers/libservers.la \
	helper/libhelper.la \
	http/libhttp.la \
	ftp/libftp.la \
	parser/libparser.la \
	anyp/libanyp.la \
	ident/libident.la \
	acl/libacls.la \
	eui/libeui.la \
	acl/libstate.la \
	acl/libapi.la \
	dns/libdns.la \
	base/libbase.la \
	ip/libip.la \
	fs/libfs.la \
	$(SSL_LIBS) \
	ipc/libipc.la \
	mgr/libmgr.la \
	$(SNMP_LIBS) \
	icmp/libicmp.la \
	comm/libcomm.la \
	log/liblog.la \
	format/libformat.la \
	store/libstore.la \
	sbuf/libsbuf.la \
	$(REGEXLIB) \
	$(REPL_OBJS) \
	$(ADAPTATION_LIBS) \
	$(ESI_LIBS) \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(NETTLELIB) \
	$(SSLLIB) \
	$(KRB5LIBS) \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testURL_LDFLAGS = $(LIBADD_DL)

tests_testSBuf_SOURCES= \
	tests/testSBuf.h \
	tests/testSBuf.cc \
	tests/SBufFindTest.h \
	tests/SBufFindTest.cc \
	tests/stub_SBufDetailedStats.cc \
	tests/stub_time.cc \
	tests/stub_debug.cc \
	tests/stub_fatal.cc \
	tests/stub_libmem.cc
nodist_tests_testSBuf_SOURCES=$(TESTSOURCES)
tests_testSBuf_LDFLAGS = $(LIBADD_DL)
tests_testSBuf_LDADD= \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testSBufList_SOURCES= \
	tests/testSBufList.h \
	tests/testSBufList.cc \
	tests/stub_SBufDetailedStats.cc \
	tests/stub_time.cc \
	tests/stub_debug.cc \
	tests/stub_fatal.cc \
	tests/stub_libmem.cc
nodist_tests_testSBufList_SOURCES=$(TESTSOURCES)
tests_testSBufList_LDFLAGS = $(LIBADD_DL)
tests_testSBufList_LDADD=\
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testConfigParser_SOURCES = \
	ClientInfo.h \
	tests/stub_MemBuf.cc \
	tests/stub_time.cc \
	tests/stub_SBufDetailedStats.cc \
	String.cc \
	ConfigParser.cc \
	fatal.h \
	tests/stub_fatal.cc \
	tests/testConfigParser.cc \
	tests/testConfigParser.h \
	cache_cf.h \
	tests/stub_cache_cf.cc \
	tests/stub_cbdata.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_HelperChildConfig.cc \
	tools.h \
	tests/stub_tools.cc \
	wordlist.h \
	wordlist.cc
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

tests_testStatHist_SOURCES = \
	tests/stub_cbdata.cc \
	fatal.h \
	tests/stub_fatal.cc \
	tests/stub_MemBuf.cc \
	tests/stub_SBufDetailedStats.cc \
	StatHist.cc \
	StatHist.h \
	String.cc \
	tests/stub_cache_manager.cc \
	tests/stub_comm.cc \
	tests/stub_debug.cc \
	tests/stub_DelayId.cc \
	tests/stub_HelperChildConfig.cc \
	tests/stub_libmem.cc \
	tests/stub_MemObject.cc \
	mime.h \
	tests/stub_mime.cc \
	tests/stub_pconn.cc \
	tests/stub_stmem.cc \
	repl_modules.h \
	tests/stub_store.cc \
	tests/stub_store_stats.cc \
	time.cc \
	tools.h \
	tests/stub_tools.cc \
	tests/testStatHist.cc \
	tests/testStatHist.h
nodist_tests_testStatHist_SOURCES = \
	$(TESTSOURCES)
tests_testStatHist_LDFLAGS = $(LIBADD_DL)
tests_testStatHist_LDADD = \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(top_builddir)/lib/libmisccontainers.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB)

tests_testLookupTable_SOURCES = \
	tests/testLookupTable.h \
	tests/testLookupTable.cc \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/stub_SBufDetailedStats.cc \
	base/LookupTable.h
nodist_tests_testLookupTable_SOURCES = $(TESTSOURCES)
tests_testLookupTable_LDFLAGS = $(LIBADD_DL)
tests_testLookupTable_LDADD = \
	sbuf/libsbuf.la \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testEnumIterator_SOURCES = \
	base/EnumIterator.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	tests/testEnumIterator.h \
	tests/testEnumIterator.cc
nodist_tests_testEnumIterator_SOURCES = \
	$(TESTSOURCES)
tests_testEnumIterator_LDFLAGS = $(LIBADD_DL)
tests_testEnumIterator_LDADD = \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

tests_testYesNoNone_SOURCES = \
	tests/testYesNoNone.cc \
	tests/testYesNoNone.h
nodist_tests_testYesNoNone_SOURCES = \
	tests/STUB.h \
	tests/stub_debug.cc \
	tests/stub_libmem.cc \
	base/YesNoNone.h
tests_testYesNoNone_LDADD= \
	base/libbase.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
tests_testYesNoNone_LDFLAGS = $(LIBADD_DL)

TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/*.h $(srcdir)/DiskIO/*.h $(srcdir)/DiskIO/*/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1
## src/repl/ has no .h files and its own makefile.

CLEANFILES += testHeaders
.PHONY: testHeaders

