#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.39 2002/10/19 01:23:22 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

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

if USE_DELAY_POOLS
DELAY_POOL_SOURCE = delay_pools.cc
else
DELAY_POOL_SOURCE = 
endif

if ENABLE_XPROF_STATS
XPROF_STATS_SOURCE = ProfStats.cc
else
XPROF_STATS_SOURCE = 
endif

if ENABLE_HTCP
HTCPSOURCE = htcp.cc
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

if ENABLE_SSL
SSLSOURCE = ssl_support.cc
else
SSLSOURCE = 
endif

if ENABLE_WIN32SPECIFIC
WIN32SOURCE = win32.cc
else
WIN32SOURCE = 
endif

AM_CFLAGS = -Werror -Wall
AM_CXXFLAGS = -Werror -Wall

SUBDIRS		= fs repl auth

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include

EXTRA_PROGRAMS = \
	unlinkd \
	pinger \
	dnsserver \
	recv-announce

noinst_PROGRAMS = \
	cf_gen

sbin_PROGRAMS = \
	squid

bin_PROGRAMS = \
	squidclient

libexec_PROGRAMS = \
	$(PINGER) \
	$(DNSSERVER) \
	$(UNLINKD) \
	cachemgr$(CGIEXT)

cf_gen_SOURCES = cf_gen.cc defines.h
nodist_cf_gen_HEADER = cf_gen_defines.h
cf_gen.$(OBJEXT): cf_gen_defines.h
squidclient_SOURCES = client.cc
cachemgr__CGIEXT__SOURCES = cachemgr.cc

EXTRA_squid_SOURCES = \
	delay_pools.cc \
	dns.cc \
	dnsserver.cc \
	dns_internal.cc \
	htcp.cc \
	leakfinder.cc \
	snmp_core.cc \
	snmp_agent.cc \
	unlinkd.cc \
	ssl_support.cc \
	ssl_support.h \
	win32.cc

squid_SOURCES = \
	access_log.cc \
	acl.cc \
	asn.cc \
	authenticate.cc \
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
	debug.cc \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.cc \
	$(DNSSOURCE) \
	enums.h \
	errorpage.cc \
	ETag.cc \
	event.cc \
	external_acl.cc \
	fd.cc \
	filemap.cc \
	forward.cc \
	fqdncache.cc \
	ftp.cc \
	globals.h \
	gopher.cc \
	helper.cc \
	$(HTCPSOURCE) \
	http.cc \
	HttpStatusLine.cc \
	HttpHdrCc.cc \
	HttpHdrRange.cc \
	HttpHdrContRange.cc \
	HttpHeader.cc \
	HttpHeaderTools.cc \
	HttpBody.cc \
	HttpMsg.cc \
	HttpReply.cc \
	HttpRequest.cc \
	icmp.cc \
	icp_v2.cc \
	icp_v3.cc \
	ident.cc \
	internal.cc \
	ipc.cc \
	ipcache.cc \
	IPInterception.cc \
	IPInterception.h \
	$(LEAKFINDERSOURCE) \
	logfile.cc \
	main.cc \
	mem.cc \
	MemBuf.cc \
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
	ssl.cc \
	$(SSLSOURCE) \
	stat.cc \
	StatHist.cc \
	String.cc \
	stmem.cc \
	store.cc \
	Store.h \
	store_io.cc \
	StoreIOBuffer.h \
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
	tools.cc \
	typedefs.h \
	ufscommon.cc \
	ufscommon.h \
	$(UNLINKDSOURCE) \
	url.cc \
	urn.cc \
	useragent.cc \
	wais.cc \
	wccp.cc \
	whois.cc \
	$(WIN32SOURCE)

nodist_squid_SOURCES = \
	repl_modules.cc \
	auth_modules.cc \
	store_modules.cc \
	cf_parser.h \
	globals.c \
	string_arrays.c

squid_LDADD = \
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
	@XTRA_LIBS@
squid_DEPENDENCIES = $(top_builddir)/lib/libmiscutil.a

unlinkd_SOURCES = unlinkd.cc
unlinkd_CXXFLAGS = -DUNLINK_DAEMON

pinger_SOURCES = \
	pinger.cc \
	debug.cc

dnsserver_SOURCES = dnsserver.cc
recv_announce_SOURCES = recv-announce.cc

nodist_pinger_SOURCES = \
	globals.c

BUILT_SOURCES = \
	cf_gen_defines.h \
	cf_parser.h \
	globals.c \
	string_arrays.c \
	repl_modules.cc \
	auth_modules.cc \
	store_modules.cc

sysconf_DATA = \
	squid.conf.default \
	mime.conf.default

data_DATA = \
	mib.txt

LDADD = -L../lib -lmiscutil @XTRA_LIBS@

EXTRA_DIST = \
	cf_gen_defines \
	cf.data.pre \
	mk-globals-c.pl \
	mk-string-arrays.pl \
	auth_modules.sh \
	store_modules.sh \
	repl_modules.sh \
	mib.txt \
	mime.conf.default

DEFAULT_PREFIX		= $(prefix)
DEFAULT_CONFIG_FILE     = $(sysconfdir)/squid.conf
DEFAULT_MIME_TABLE	= $(sysconfdir)/mime.conf
DEFAULT_DNSSERVER       = $(libexecdir)/dnsserver$(EXEEXT)
DEFAULT_LOG_PREFIX	= $(localstatedir)/logs
DEFAULT_CACHE_LOG       = $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG      = $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG       = $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_PID_FILE        = $(DEFAULT_LOG_PREFIX)/squid.pid
DEFAULT_SWAP_DIR        = $(localstatedir)/cache
DEFAULT_PINGER		= $(libexecdir)/pinger$(EXEEXT)
DEFAULT_UNLINKD		= $(libexecdir)/unlinkd$(EXEEXT)
DEFAULT_DISKD		= $(libexecdir)/diskd$(EXEEXT)
DEFAULT_ICON_DIR	= $(datadir)/icons
DEFAULT_ERROR_DIR	= $(datadir)/errors/@ERR_DEFAULT_LANGUAGE@
DEFAULT_MIB_PATH	= $(datadir)/mib.txt
DEFAULT_HOSTS		= @OPT_DEFAULT_HOSTS@

DEFS = @DEFS@ -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\"

$(OBJS): $(top_srcdir)/include/version.h ../include/autoconf.h

snmp_core.o snmp_agent.o: ../snmplib/libsnmp.a $(top_srcdir)/include/cache_snmp.h

globals.c: globals.h mk-globals-c.pl
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
	s%@DEFAULT_HOSTS@%$(DEFAULT_HOSTS)%g;"\
	< $(srcdir)/cf.data.pre >$@

store_modules.cc: store_modules.sh Makefile
	$(SHELL) $(srcdir)/store_modules.sh $(STORE_MODULES) >store_modules.cc

repl_modules.cc: repl_modules.sh Makefile
	$(SHELL) $(srcdir)/repl_modules.sh $(REPL_POLICIES) > repl_modules.cc

auth_modules.cc: auth_modules.sh Makefile
	@$(SHELL) $(srcdir)/auth_modules.sh $(AUTH_MODULES) >auth_modules.cc

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
	@if test -f $(DESTDIR)$(DEFAULT_CONFIG_FILE) ; then \
		echo "rm -f $(DESTDIR)$(DEFAULT_CONFIG_FILE)"; \
		$(RM) -f $(DESTDIR)$(DEFAULT_CONFIG_FILE); \
	fi

DISTCLEANFILES = cf_gen_defines.h cf.data cf_parser.h squid.conf.default \
	globals.c string_arrays.c repl_modules.cc auth_modules.cc store_modules.cc

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

