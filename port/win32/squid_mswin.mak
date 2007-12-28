THISMAKEFILE	= squid_mswin.mak

prefix		= c:/squid
exec_prefix	= $(prefix)/bin
exec_suffix	= .exe
cgi_suffix	= .cgi
top_srcdir	= ..\..
bindir		= $(exec_prefix)
libexecdir      = $(prefix)/libexec
sysconfdir	= $(prefix)/etc
datadir		= $(prefix)/share
localstatedir   = $(prefix)/var
srcdir		= ..\..\src
docdir		= ..\..\doc
win32includedir = .\include
iconsdir		= $(top_srcdir)\icons

# Gotta love the DOS legacy
#
SQUID_EXE	= squid$(exec_suffix)
CLIENT_EXE	= client$(exec_suffix)
DNSSERVER_EXE	= dnsserver$(exec_suffix)
UNLINKD_EXE	= unlinkd$(exec_suffix)
PINGER_EXE	= pinger$(exec_suffix)
CACHEMGR_EXE	= cachemgr$(cgi_suffix)
DISKD_EXE	= diskd$(exec_suffix)

DEFAULT_HTTP_PORT	= 3128
DEFAULT_ICP_PORT	= 3130
DEFAULT_PREFIX		= $(prefix)
DEFAULT_CONFIG_FILE     = $(sysconfdir)/squid.conf
DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf
DEFAULT_MIME_TABLE	= $(sysconfdir)/mime.conf
DEFAULT_DNSSERVER       = $(libexecdir)/$(DNSSERVER_EXE)
DEFAULT_LOG_PREFIX 	= $(localstatedir)/logs
DEFAULT_CACHE_LOG       = $(DEFAULT_LOG_PREFIX)/cache.log
DEFAULT_ACCESS_LOG      = $(DEFAULT_LOG_PREFIX)/access.log
DEFAULT_STORE_LOG       = $(DEFAULT_LOG_PREFIX)/store.log
DEFAULT_PID_FILE        = $(DEFAULT_LOG_PREFIX)/squid.pid
DEFAULT_SWAP_DIR        = $(localstatedir)/cache
DEFAULT_PINGER		= $(libexecdir)/$(PINGER_EXE)
DEFAULT_UNLINKD		= $(libexecdir)/$(UNLINKD_EXE)
DEFAULT_DISKD		= $(libexecdir)/$(DISKD_EXE)
DEFAULT_ICON_DIR	= $(datadir)/icons
DEFAULT_ERROR_DIR	= $(datadir)/errors/English
DEFAULT_MIB_PATH	= $(datadir)/mib.txt
DEFAULT_HOSTS		= none
!INCLUDE squid_version.mak

REPL_POLICIES = lru heap

SUBSTITUTE=sed "\
	s%@DEFAULT_CONFIG_FILE@%$(DEFAULT_CONFIG_FILE)%g;\
	s%@DEFAULT_CACHEMGR_CONFIG@%$(DEFAULT_CACHEMGR_CONFIG)%g;\
	s%@DEFAULT_ERROR_DIR@%$(DEFAULT_ERROR_DIR)%g;\
	s%@DEFAULT_MIME_TABLE@%$(DEFAULT_MIME_TABLE)%g;\
	s%@PACKAGE_STRING@%$(PACKAGE_STRING)%g;\
	"

cf_gen_defines.h: $(srcdir)\cf_gen_defines $(srcdir)\cf.data.pre
	gawk -f $(srcdir)\cf_gen_defines <$(srcdir)\cf.data.pre >$(srcdir)\cf_gen_defines.h

cf.data: $(srcdir)\cf.data.pre .\$(THISMAKEFILE)
	sed "\
	s%@DEFAULT_HTTP_PORT@%$(DEFAULT_HTTP_PORT)%g;\
	s%@DEFAULT_ICP_PORT@%$(DEFAULT_ICP_PORT)%g;\
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
	< $(srcdir)\cf.data.pre >$(srcdir)\cf.data

repl_modules.cc: .\repl_modules.cmd .\$(THISMAKEFILE)
	.\repl_modules.cmd $(REPL_POLICIES) >$(srcdir)\repl_modules.cc

default_config_file.h: .\$(THISMAKEFILE)
	.\default_config_file.cmd $(DEFAULT_CONFIG_FILE) $(DEFAULT_ERROR_DIR) $(DEFAULT_CACHEMGR_CONFIG) >$(win32includedir)\default_config_file.h
	
icons: .\icons.cmd $(iconsdir)\icons.shar
	.\icons.cmd $(iconsdir)

squid.8: $(docdir)\squid.8.in .\$(THISMAKEFILE)
	$(SUBSTITUTE) < $(docdir)\squid.8.in > $(docdir)\squid.8

cachemgr.cgi.8: $(docdir)\cachemgr.cgi.8.in .\$(THISMAKEFILE)
	$(SUBSTITUTE) < $(docdir)\cachemgr.cgi.8.in > $(docdir)\cachemgr.cgi.8
