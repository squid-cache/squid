#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.12 2001/11/28 03:02:42 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#

if USE_DNSSERVER
DNSSOURCE = dns.c
DNSSERVER = dnsserver
else
DNSSOURCE = dns_internal.c
DNSSERVER =
endif

if USE_SNMP
SNMPSOURCE = snmp_core.c snmp_agent.c
else
SNMPSOURCE = 
endif

if USE_DELAY_POOLS
DELAY_POOL_SOURCE = delay_pools.c
else
DELAY_POOL_SOURCE = 
endif

if ENABLE_HTCP
HTCPSOURCE = htcp.c
endif

if MAKE_LEAKFINDER
LEAKFINDERSOURCE =  leakfinder.c
else
LEAKFINDERSOURCE = 
endif

if ENABLE_UNLINKD
UNLINKDSOURCE = unlinkd.c
UNLINKD = unlinkd
UNLINKD_EXE = unlinkd$(EXEEXT)
else
UNLINKDSOURCE = 
UNLINKD = 
UNLINKD_EXE =
endif

if ENABLE_SSL
SSLSOURCE = ssl_support.c
else
SSLSOURCE = 
endif

if ENABLE_WIN32SPECIFIC
WIN32SOURCE = win32.c
else
WIN32SOURCE = 
endif

SUBDIRS		= fs repl auth

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include

EXTRA_PROGRAMS = \
	unlinkd \
	pinger \
	dnsserver

noinst_PROGRAMS = \
	cf_gen

bin_PROGRAMS = \
	squid \
	client

libexec_PROGRAMS = \
	@OPT_PINGER@ \
	$(DNSSERVER) \
	$(UNLINKD) \
	cachemgr

cf_gen_SOURCES = cf_gen.c defines.h
nodist_cf_gen_HEADER = cf_gen_defines.h
cf_gen.$(OBJEXT): cf_gen_defines.h

EXTRA_squid_SOURCES = \
	delay_pools.c \
	dns.c \
	dnsserver.c \
	dns_internal.c \
	htcp.c \
	leakfinder.c \
	snmp_core.c \
	snmp_agent.c \
	unlinkd.c \
	ssl_support.c \
	win32.c

squid_SOURCES = \
	access_log.c \
	acl.c \
	asn.c \
	authenticate.c \
	cache_cf.c \
	CacheDigest.c \
	cache_manager.c \
	carp.c \
	cbdata.c \
	client_db.c \
	client_side.c \
	comm.c \
	comm_select.c \
	debug.c \
	defines.h \
	$(DELAY_POOL_SOURCE) \
	disk.c \
	$(DNSSOURCE) \
	enums.h \
	errorpage.c \
	ETag.c \
	event.c \
	fd.c \
	filemap.c \
	forward.c \
	fqdncache.c \
	ftp.c \
	globals.h \
	gopher.c \
	helper.c \
	$(HTCPSOURCE) \
	http.c \
	HttpStatusLine.c \
	HttpHdrCc.c \
	HttpHdrRange.c \
	HttpHdrContRange.c \
	HttpHeader.c \
	HttpHeaderTools.c \
	HttpBody.c \
	HttpMsg.c \
	HttpReply.c \
	HttpRequest.c \
	icmp.c \
	icp_v2.c \
	icp_v3.c \
	ident.c \
	internal.c \
	ipc.c \
	ipcache.c \
	$(LEAKFINDERSOURCE) \
	logfile.c \
	main.c \
	mem.c \
	MemPool.c \
	MemBuf.c \
	mime.c \
	multicast.c \
	neighbors.c \
	net_db.c \
	Packer.c \
	pconn.c \
	peer_digest.c \
	peer_select.c \
	protos.h \
	redirect.c \
	referer.c \
	refresh.c \
	send-announce.c \
	$(SNMPSOURCE) \
	squid.h \
	ssl.c \
	$(SSLSOURCE) \
	stat.c \
	StatHist.c \
	String.c \
	stmem.c \
	store.c \
	store_io.c \
	store_client.c \
	store_digest.c \
	store_dir.c \
	store_key_md5.c \
	store_log.c \
	store_rebuild.c \
	store_swapin.c \
	store_swapmeta.c \
	store_swapout.c \
	structs.h \
	tools.c \
	typedefs.h \
	$(UNLINKDSOURCE) \
	url.c \
	urn.c \
	useragent.c \
	wais.c \
	wccp.c \
	whois.c \
	$(WIN32SOURCE)

nodist_squid_SOURCES = \
	repl_modules.c \
	auth_modules.c \
	store_modules.c \
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
	@SQUID_AIO_LIB@ \
	@SQUID_PTHREAD_LIB@ \
	@SNMPLIB@ \
	@LIB_MALLOC@ \
	@SSLLIB@ \
	-lmiscutil \
	@XTRA_LIBS@

unlinkd_SOURCES = 
unlinkd_LDADD = unlinkd-daemon.o
unlinkd-daemon.o: unlinkd.c
	$(COMPILE) -DUNLINK_DAEMON -c $(srcdir)/unlinkd.c -o $@

pinger_SOURCES = \
	pinger.c \
	debug.c \
	globals.c

BUILT_SOURCES = \
	cf_gen_defines.h \
	cf_parser.h \
	globals.c \
	string_arrays.c \
	repl_modules.c \
	auth_modules.c \
	store_modules.c

sysconf_DATA = \
	squid.conf.default \
	mib.txt \
	mime.conf.default

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
DEFAULT_DNSSERVER       = $(libexecdir)/@OPT_DNSSERVER_EXE@
DEFAULT_LOG_PREFIX	= $(localstatedir)/logs
DEFAULT_CACHE_LOG       = $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG      = $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG       = $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_PID_FILE        = $(DEFAULT_LOG_PREFIX)/squid.pid
DEFAULT_SWAP_DIR        = $(localstatedir)/cache
DEFAULT_PINGER		= $(libexecdir)/@OPT_PINGER_EXE@
DEFAULT_UNLINKD		= $(libexecdir)/$(UNLINKD_EXE)
DEFAULT_DISKD		= $(libexecdir)/@OPT_DISKD_EXE@
DEFAULT_ICON_DIR	= $(sharedstatedir)/squid/icons
DEFAULT_ERROR_DIR	= $(sharedstatedir)/squid/errors/@ERR_DEFAULT_LANGUAGE@
DEFAULT_MIB_PATH	= $(sysconfdir)/mib.txt

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
	s%@DEFAULT_PREFIX@%$(DEFAULT_PREFIX)%g;"\
	< $(srcdir)/cf.data.pre >$@

store_modules.c: store_modules.sh Makefile
	$(SHELL) $(srcdir)/store_modules.sh $(STORE_MODULES) >store_modules.c

repl_modules.c: repl_modules.sh Makefile
	$(SHELL) $(srcdir)/repl_modules.sh $(REPL_POLICIES) > repl_modules.c

auth_modules.c: auth_modules.sh Makefile
	@$(SHELL) $(srcdir)/auth_modules.sh $(AUTH_MODULES) >auth_modules.c

install-data-local: install-sysconfDATA
	@if test -f $(DESTDIR)$(sysconfdir)/mime.conf ; then \
	        echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/mime.conf" ; \
	else \
	        echo "$(INSTALL_DATA) $(srcdir)/mime.conf.default $(DESTDIR)$(sysconfdir)/mime.conf" ;\
	        $(INSTALL_DATA) $(srcdir)/mime.conf.default $(DESTDIR)$(sysconfdir)/mime.conf; \
	fi
	@if test -f $(DESTDIR)$(sysconfdir)/squid.conf ; then \
	        echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/squid.conf" ; \
	else \
	        echo "$(INSTALL_DATA) squid.conf.default $(DESTDIR)$(sysconfdir)/squid.conf"; \
	        $(INSTALL_DATA) squid.conf.default $(DESTDIR)$(sysconfdir)/squid.conf; \
	fi
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_LOG_PREFIX)

uninstall-local:
	@if test -f $(DESTDIR)$(sysconfdir)/mime.conf ; then \
		echo "rm -f $(DESTDIR)$(sysconfdir)/mime.conf"; \
		$(RM) -f $(DESTDIR)$(sysconfdir)/mime.conf; \
	fi
	@if test -f $(DESTDIR)$(sysconfdir)/squid.conf ; then \
		echo "rm -f $(DESTDIR)$(sysconfdir)/squid.conf"; \
		$(RM) -f $(DESTDIR)$(sysconfdir)/squid.conf; \
	fi

DISTCLEANFILES = cf_gen_defines.h cf.data cf_parser.h squid.conf.default \
	globals.c string_arrays.c repl_modules.c auth_modules.c store_modules.c

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

