
/*
 * $Id: protos.h,v 1.506 2005/06/09 07:07:30 hno Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_PROTOS_H
#define SQUID_PROTOS_H

#if FORW_VIA_DB
SQUIDCEXTERN void fvdbCountVia(const char *key);
SQUIDCEXTERN void fvdbCountForw(const char *key);
#endif
#if HEADERS_LOG
SQUIDCEXTERN void headersLog(int cs, int pq, method_t m, void *data);
#endif
SQUIDCEXTERN char *log_quote(const char *header);
SQUIDCEXTERN int logTypeIsATcpHit(log_type);

/*
 * cache_cf.c
 */
SQUIDCEXTERN int parseConfigFile(const char *file_name);
SQUIDCEXTERN const char *wordlistAdd(wordlist **, const char *);
SQUIDCEXTERN void wordlistAddWl(wordlist **, wordlist *);
SQUIDCEXTERN void wordlistJoin(wordlist **, wordlist **);
SQUIDCEXTERN wordlist *wordlistDup(const wordlist *);
SQUIDCEXTERN void wordlistDestroy(wordlist **);
SQUIDCEXTERN void configFreeMemory(void);
SQUIDCEXTERN void wordlistCat(const wordlist *, MemBuf * mb);
SQUIDCEXTERN void self_destruct(void);
SQUIDCEXTERN void add_http_port(char *portspec);
extern int xatoi(const char *token);
extern long xatol(const char *token);


/* extra functions from cache_cf.c useful for lib modules */
SQUIDCEXTERN void parse_int(int *var);
SQUIDCEXTERN void parse_onoff(int *var);
SQUIDCEXTERN void parse_eol(char *volatile *var);
SQUIDCEXTERN void parse_wordlist(wordlist ** list);
SQUIDCEXTERN void requirePathnameExists(const char *name, const char *path);
SQUIDCEXTERN void parse_time_t(time_t * var);

SQUIDCEXTERN void parse_sockaddr_in_list_token(sockaddr_in_list **, char *);


/*
 * cbdata.c
 */
SQUIDCEXTERN void cbdataInit(void);
#if CBDATA_DEBUG
SQUIDCEXTERN void *cbdataInternalAllocDbg(cbdata_type type, const char *, int);
SQUIDCEXTERN void *cbdataInternalFreeDbg(void *p, const char *, int);
SQUIDCEXTERN void cbdataInternalLockDbg(const void *p, const char *, int);
SQUIDCEXTERN void cbdataInternalUnlockDbg(const void *p, const char *, int);
SQUIDCEXTERN int cbdataInternalReferenceDoneValidDbg(void **p, void **tp, const char *, int);
#else
SQUIDCEXTERN void *cbdataInternalAlloc(cbdata_type type);
SQUIDCEXTERN void *cbdataInternalFree(void *p);
SQUIDCEXTERN void cbdataInternalLock(const void *p);
SQUIDCEXTERN void cbdataInternalUnlock(const void *p);
SQUIDCEXTERN int cbdataInternalReferenceDoneValid(void **p, void **tp);
#endif
SQUIDCEXTERN int cbdataReferenceValid(const void *p);
SQUIDCEXTERN cbdata_type cbdataInternalAddType(cbdata_type type, const char *label, int size, FREE * free_func);

/* client_side.c - FD related client side routines */

SQUIDCEXTERN void clientdbInit(void);

SQUIDCEXTERN void clientdbUpdate(struct IN_ADDR, log_type, protocol_t, size_t);

SQUIDCEXTERN int clientdbCutoffDenied(struct IN_ADDR);
SQUIDCEXTERN void clientdbDump(StoreEntry *);
SQUIDCEXTERN void clientdbFreeMemory(void);

SQUIDCEXTERN int clientdbEstablished(struct IN_ADDR, int);
SQUIDCEXTERN void clientOpenListenSockets(void);
SQUIDCEXTERN void clientHttpConnectionsClose(void);
SQUIDCEXTERN void clientReadBody(HttpRequest * req, char *buf, size_t size, CBCB * callback, void *data);
SQUIDCEXTERN int clientAbortBody(HttpRequest * req);
SQUIDCEXTERN void httpRequestFree(void *);

extern void clientAccessCheck(void *);

/* comm.c */
extern void comm_calliocallback(void);
extern bool comm_iocallbackpending(void); /* inline candidate */

extern int comm_listen(int fd);
SQUIDCEXTERN int commSetNonBlocking(int fd);
SQUIDCEXTERN int commUnsetNonBlocking(int fd);
SQUIDCEXTERN void commSetCloseOnExec(int fd);
extern void _comm_close(int fd, char const *file, int line);
#define comm_close(fd) (_comm_close((fd), __FILE__, __LINE__))
SQUIDCEXTERN void comm_reset_close(int fd);
#if LINGERING_CLOSE
SQUIDCEXTERN void comm_lingering_close(int fd);
#endif
SQUIDCEXTERN void commConnectStart(int fd, const char *, u_short, CNCB *, void *);

SQUIDCEXTERN int comm_connect_addr(int sock, const struct sockaddr_in *);
SQUIDCEXTERN void comm_init(void);

SQUIDCEXTERN int comm_open(int, int, struct IN_ADDR, u_short port, int, const char *note);

SQUIDCEXTERN int comm_openex(int, int, struct IN_ADDR, u_short, int, unsigned char TOS, const char *);
SQUIDCEXTERN u_short comm_local_port(int fd);

SQUIDCEXTERN void commSetSelect(int, unsigned int, PF *, void *, time_t);

SQUIDCEXTERN int comm_udp_sendto(int, const struct sockaddr_in *, int, const void *, int);
SQUIDCEXTERN void comm_old_write(int fd,
                                 const char *buf,
                                 int size,
                                 CWCB * handler,
                                 void *handler_data,
                                 FREE *);
SQUIDCEXTERN void comm_old_write_mbuf(int fd, MemBuf mb, CWCB * handler, void *handler_data);
SQUIDCEXTERN void commCallCloseHandlers(int fd);
SQUIDCEXTERN int commSetTimeout(int fd, int, PF *, void *);
SQUIDCEXTERN int ignoreErrno(int);
SQUIDCEXTERN void commCloseAllSockets(void);
SQUIDCEXTERN void checkTimeouts(void);


/*
 * comm_select.c
 */
SQUIDCEXTERN void comm_select_init(void);
SQUIDCEXTERN comm_err_t comm_select(int);
SQUIDCEXTERN void comm_quick_poll_required(void);

SQUIDCEXTERN void packerToStoreInit(Packer * p, StoreEntry * e);
SQUIDCEXTERN void packerToMemInit(Packer * p, MemBuf * mb);
SQUIDCEXTERN void packerClean(Packer * p);
SQUIDCEXTERN void packerAppend(Packer * p, const char *buf, int size);
#if STDC_HEADERS
SQUIDCEXTERN void
packerPrintf(Packer * p, const char *fmt,...) PRINTF_FORMAT_ARG2;
#else
SQUIDCEXTERN void packerPrintf();
#endif


/* see debug.c for info on context-based debugging */
SQUIDCEXTERN Ctx ctx_enter(const char *descr);
SQUIDCEXTERN void ctx_exit(Ctx ctx);

SQUIDCEXTERN void _db_set_syslog(const char *facility);
SQUIDCEXTERN void _db_init(const char *logfile, const char *options);
SQUIDCEXTERN void _db_rotate_log(void);

#if STDC_HEADERS
SQUIDCEXTERN void _db_print(const char *,...) PRINTF_FORMAT_ARG1;
#else
SQUIDCEXTERN void _db_print();
#endif
extern void xassert(const char *, const char *, int);

/* packs, then prints an object using debug() */
SQUIDCEXTERN void debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm);

/* disk.c */
SQUIDCEXTERN int file_open(const char *path, int mode);
SQUIDCEXTERN void file_close(int fd);
/* Adapter file_write for object callbacks */

template <class O>
void
FreeObject(void *address)
{
    O *anObject = static_cast <O *>(address);
    delete anObject;
}

SQUIDCEXTERN void file_write(int, off_t, void const *, int len, DWCB *, void *, FREE *);
SQUIDCEXTERN void file_write_mbuf(int fd, off_t, MemBuf mb, DWCB * handler, void *handler_data);
SQUIDCEXTERN void file_read(int, char *, int, off_t, DRCB *, void *);
SQUIDCEXTERN void disk_init(void);

/* diskd.c */
SQUIDCEXTERN diskd_queue *afile_create_queue(void);
SQUIDCEXTERN void afile_destroy_queue(diskd_queue *);
SQUIDCEXTERN void afile_sync_queue(diskd_queue *);
SQUIDCEXTERN void afile_sync(void);
SQUIDCEXTERN void afile_open(const char *path, int mode, DOCB *, void *);
SQUIDCEXTERN void afile_close(int fd, DCCB * callback, void *data);
SQUIDCEXTERN void afile_write(int, off_t, void *, int len, DWCB *, void *, FREE *);
SQUIDCEXTERN void afile_write_mbuf(int fd, off_t, MemBuf, DWCB *, void *);
SQUIDCEXTERN void afile_read(int, char *, int, off_t, DRCB *, void *);
SQUIDCEXTERN void afile_unlink(const char *path, DUCB *, void *);
SQUIDCEXTERN void afile_truncate(const char *path, DTCB *, void *);

SQUIDCEXTERN void dnsShutdown(void);
SQUIDCEXTERN void dnsInit(void);
SQUIDCEXTERN void dnsSubmit(const char *lookup, HLPCB * callback, void *data);

/* dns_internal.c */
SQUIDCEXTERN void idnsInit(void);
SQUIDCEXTERN void idnsShutdown(void);
SQUIDCEXTERN void idnsALookup(const char *, IDNSCB *, void *);

SQUIDCEXTERN void idnsPTRLookup(const struct IN_ADDR, IDNSCB *, void *);

extern void eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata=true);
SQUIDCEXTERN void eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int);
SQUIDCEXTERN void eventRun(void);
SQUIDCEXTERN int eventNextTime(void);
SQUIDCEXTERN void eventDelete(EVH * func, void *arg);
SQUIDCEXTERN void eventInit(void);
SQUIDCEXTERN void eventFreeMemory(void);
SQUIDCEXTERN int eventFind(EVH *, void *);

SQUIDCEXTERN void fd_close(int fd);
SQUIDCEXTERN void fd_open(int fd, unsigned int type, const char *);
SQUIDCEXTERN void fd_note(int fd, const char *);
SQUIDCEXTERN void fd_bytes(int fd, int len, unsigned int type);
SQUIDCEXTERN void fdFreeMemory(void);
SQUIDCEXTERN void fdDumpOpen(void);
SQUIDCEXTERN int fdNFree(void);
SQUIDCEXTERN int fdUsageHigh(void);
SQUIDCEXTERN void fdAdjustReserved(void);

SQUIDCEXTERN fileMap *file_map_create(void);
SQUIDCEXTERN int file_map_allocate(fileMap *, int);
SQUIDCEXTERN int file_map_bit_set(fileMap *, int);
SQUIDCEXTERN int file_map_bit_test(fileMap *, int);
SQUIDCEXTERN void file_map_bit_reset(fileMap *, int);
SQUIDCEXTERN void filemapFreeMemory(fileMap *);


SQUIDCEXTERN void fqdncache_nbgethostbyaddr(struct IN_ADDR, FQDNH *, void *);

SQUIDCEXTERN const char *fqdncache_gethostbyaddr(struct IN_ADDR, int flags);
SQUIDCEXTERN void fqdncache_init(void);
SQUIDCEXTERN void fqdnStats(StoreEntry *);
SQUIDCEXTERN void fqdncacheReleaseInvalid(const char *);

SQUIDCEXTERN const char *fqdnFromAddr(struct IN_ADDR);
SQUIDCEXTERN int fqdncacheQueueDrain(void);
SQUIDCEXTERN void fqdncacheFreeMemory(void);
SQUIDCEXTERN void fqdncache_restart(void);
SQUIDCEXTERN EVH fqdncache_purgelru;
SQUIDCEXTERN void fqdncacheAddEntryFromHosts(char *addr, wordlist * hostnames);

SQUIDCEXTERN void ftpStart(FwdState *);
SQUIDCEXTERN char *ftpUrlWith2f(const HttpRequest *);

SQUIDCEXTERN void gopherStart(FwdState *);
SQUIDCEXTERN int gopherCachable(const HttpRequest *);


SQUIDCEXTERN void whoisStart(FwdState *);

/* http.c */
SQUIDCEXTERN int httpCachable(method_t);
SQUIDCEXTERN void httpStart(FwdState *);
SQUIDCEXTERN mb_size_t httpBuildRequestPrefix(HttpRequest * request,
        HttpRequest * orig_request,
        StoreEntry * entry,
        MemBuf * mb,
        http_state_flags);
SQUIDCEXTERN void httpAnonInitModule(void);
SQUIDCEXTERN int httpAnonHdrAllowed(http_hdr_type hdr_id);
SQUIDCEXTERN int httpAnonHdrDenied(http_hdr_type hdr_id);
SQUIDCEXTERN void httpBuildRequestHeader(HttpRequest *, HttpRequest *, StoreEntry *, HttpHeader *, http_state_flags);
SQUIDCEXTERN const char *httpMakeVaryMark(HttpRequest * request, HttpReply const * reply);

/* ETag */
SQUIDCEXTERN int etagParseInit(ETag * etag, const char *str);
SQUIDCEXTERN int etagIsEqual(const ETag * tag1, const ETag * tag2);

SQUIDCEXTERN const char *httpStatusString(http_status status);

/* Http Body */
/* init/clean */
SQUIDCEXTERN void httpBodyInit(HttpBody * body);
SQUIDCEXTERN void httpBodyClean(HttpBody * body);
/* get body ptr (always use this) */
SQUIDCEXTERN const char *httpBodyPtr(const HttpBody * body);
/* set body, does not clone mb so you should not reuse it */
SQUIDCEXTERN void httpBodySet(HttpBody * body, MemBuf * mb);

/* pack */
SQUIDCEXTERN void httpBodyPackInto(const HttpBody * body, Packer * p);

/* Http Cache Control Header Field */
SQUIDCEXTERN void httpHdrCcInitModule(void);
SQUIDCEXTERN void httpHdrCcCleanModule(void);
SQUIDCEXTERN HttpHdrCc *httpHdrCcCreate(void);
SQUIDCEXTERN HttpHdrCc *httpHdrCcParseCreate(const String * str);
SQUIDCEXTERN void httpHdrCcDestroy(HttpHdrCc * cc);
SQUIDCEXTERN HttpHdrCc *httpHdrCcDup(const HttpHdrCc * cc);
SQUIDCEXTERN void httpHdrCcPackInto(const HttpHdrCc * cc, Packer * p);
SQUIDCEXTERN void httpHdrCcJoinWith(HttpHdrCc * cc, const HttpHdrCc * new_cc);
SQUIDCEXTERN void httpHdrCcSetMaxAge(HttpHdrCc * cc, int max_age);
SQUIDCEXTERN void httpHdrCcSetSMaxAge(HttpHdrCc * cc, int s_maxage);
SQUIDCEXTERN void httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist);
SQUIDCEXTERN void httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);

/* Http Surrogate Control Header Field */
extern void httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);
extern void httpHdrScInitModule (void);
extern void httpHdrScCleanModule (void);
extern HttpHdrSc *httpHdrScCreate(void);
extern HttpHdrSc *httpHdrScParseCreate(String const *);
extern void httpHdrScDestroy(HttpHdrSc * sc);
extern HttpHdrSc *httpHdrScDup(const HttpHdrSc * sc);
extern void httpHdrScPackInto(const HttpHdrSc * sc, Packer * p);
extern void httpHdrScJoinWith(HttpHdrSc *, const HttpHdrSc *);
extern void httpHdrScSetMaxAge(HttpHdrSc *, char const *, int);
extern void httpHdrScUpdateStats(const HttpHdrSc *, StatHist *);
extern HttpHdrScTarget * httpHdrScFindTarget (HttpHdrSc *sc, const char *target);
extern HttpHdrScTarget * httpHdrScGetMergedTarget (HttpHdrSc *sc, const char *ourtarget);

/* Http Surrogate control header field 'targets' */
extern HttpHdrScTarget * httpHdrScTargetCreate (const char *);
extern void httpHdrScTargetDestroy(HttpHdrScTarget *);
extern HttpHdrScTarget *httpHdrScTargetDup(const HttpHdrScTarget *);
extern void httpHdrScTargetPackInto(const HttpHdrScTarget *, Packer *);
extern void httpHdrScTargetSetMaxAge(HttpHdrScTarget *, int);
extern void httpHdrScTargetUpdateStats(const HttpHdrScTarget *, StatHist *);
extern void httpHdrScTargetJoinWith(HttpHdrScTarget *, const HttpHdrScTarget *);
extern void httpHdrScTargetMergeWith(HttpHdrScTarget *, const HttpHdrScTarget *);
extern void httpHdrScTargetStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);


/* Http Header Tools */
SQUIDCEXTERN HttpHeaderFieldInfo *httpHeaderBuildFieldsInfo(const HttpHeaderFieldAttrs * attrs, int count);
SQUIDCEXTERN void httpHeaderDestroyFieldsInfo(HttpHeaderFieldInfo * info, int count);
SQUIDCEXTERN http_hdr_type httpHeaderIdByName(const char *name, int name_len, const HttpHeaderFieldInfo * attrs, int end);
SQUIDCEXTERN http_hdr_type httpHeaderIdByNameDef(const char *name, int name_len);
SQUIDCEXTERN const char *httpHeaderNameById(int id);
SQUIDCEXTERN void httpHeaderMaskInit(HttpHeaderMask * mask, int value);
SQUIDCEXTERN void httpHeaderCalcMask(HttpHeaderMask * mask, const int *enums, size_t count);
SQUIDCEXTERN int httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive);
SQUIDCEXTERN void strListAdd(String * str, const char *item, char del);
SQUIDCEXTERN int strListIsMember(const String * str, const char *item, char del);
SQUIDCEXTERN int strListIsSubstr(const String * list, const char *s, char del);
SQUIDCEXTERN int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);
SQUIDCEXTERN const char *getStringPrefix(const char *str, const char *end);
SQUIDCEXTERN int httpHeaderParseInt(const char *start, int *val);
SQUIDCEXTERN int httpHeaderParseSize(const char *start, ssize_t * sz);
SQUIDCEXTERN int httpHeaderReset(HttpHeader * hdr);
#if STDC_HEADERS
SQUIDCEXTERN void
httpHeaderPutStrf(HttpHeader * hdr, http_hdr_type id, const char *fmt,...) PRINTF_FORMAT_ARG3;
#else
SQUIDCEXTERN void httpHeaderPutStrf();
#endif


/* Http Header */
SQUIDCEXTERN void httpHeaderInitModule(void);
SQUIDCEXTERN void httpHeaderCleanModule(void);
/* init/clean */
SQUIDCEXTERN void httpHeaderClean(HttpHeader * hdr);
/* append/update */
SQUIDCEXTERN void httpHeaderAppend(HttpHeader * dest, const HttpHeader * src);
/* parse/pack */
SQUIDCEXTERN int httpHeaderParse(HttpHeader * hdr, const char *header_start, const char *header_end);
SQUIDCEXTERN void httpHeaderPackInto(const HttpHeader * hdr, Packer * p);
/* field manipulation */
SQUIDCEXTERN int httpHeaderHas(const HttpHeader * hdr, http_hdr_type type);
SQUIDCEXTERN void httpHeaderPutInt(HttpHeader * hdr, http_hdr_type type, int number);
SQUIDCEXTERN void httpHeaderPutTime(HttpHeader * hdr, http_hdr_type type, time_t htime);
SQUIDCEXTERN void httpHeaderInsertTime(HttpHeader * hdr, http_hdr_type type, time_t htime);
SQUIDCEXTERN void httpHeaderPutStr(HttpHeader * hdr, http_hdr_type type, const char *str);
SQUIDCEXTERN void httpHeaderPutAuth(HttpHeader * hdr, const char *auth_scheme, const char *realm);
SQUIDCEXTERN void httpHeaderPutCc(HttpHeader * hdr, const HttpHdrCc * cc);

class HttpHdrContRange;
SQUIDCEXTERN void httpHeaderPutContRange(HttpHeader * hdr, const HttpHdrContRange * cr);

class HttpHdrRange;
SQUIDCEXTERN void httpHeaderPutRange(HttpHeader * hdr, const HttpHdrRange * range);
SQUIDCEXTERN void httpHeaderPutExt(HttpHeader * hdr, const char *name, const char *value);
SQUIDCEXTERN int httpHeaderGetInt(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN time_t httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN TimeOrTag httpHeaderGetTimeOrTag(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN HttpHdrCc *httpHeaderGetCc(const HttpHeader * hdr);
SQUIDCEXTERN ETag httpHeaderGetETag(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN HttpHdrRange *httpHeaderGetRange(const HttpHeader * hdr);
SQUIDCEXTERN HttpHdrContRange *httpHeaderGetContRange(const HttpHeader * hdr);
SQUIDCEXTERN const char *httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN const char *httpHeaderGetLastStr(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN const char *httpHeaderGetAuth(const HttpHeader * hdr, http_hdr_type id, const char *auth_scheme);
extern String httpHeaderGetList(const HttpHeader * hdr, http_hdr_type id);
extern String httpHeaderGetStrOrList(const HttpHeader * hdr, http_hdr_type id);
extern String httpHeaderGetByName(const HttpHeader * hdr, const char *name);
extern String httpHeaderGetListMember(const HttpHeader * hdr, http_hdr_type id, const char *member, const char separator);
extern String httpHeaderGetByNameListMember(const HttpHeader * hdr, const char *name, const char *member, const char separator);
SQUIDCEXTERN int httpHeaderDelByName(HttpHeader * hdr, const char *name);
SQUIDCEXTERN int httpHeaderDelById(HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos);
extern int httpHeaderEntryGetInt(const HttpHeaderEntry * e);
/* avoid using these low level routines */
SQUIDCEXTERN HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos);
SQUIDCEXTERN HttpHeaderEntry *httpHeaderFindEntry(const HttpHeader * hdr, http_hdr_type id);
SQUIDCEXTERN void httpHeaderAddEntry(HttpHeader * hdr, HttpHeaderEntry * e);
SQUIDCEXTERN void httpHeaderInsertEntry(HttpHeader * hdr, HttpHeaderEntry * e);
SQUIDCEXTERN HttpHeaderEntry *httpHeaderEntryClone(const HttpHeaderEntry * e);
SQUIDCEXTERN void httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p);
/* store report about current header usage and other stats */
SQUIDCEXTERN void httpHeaderStoreReport(StoreEntry * e);
SQUIDCEXTERN void httpHdrMangleList(HttpHeader *, HttpRequest *, int req_or_rep);

/* Http Msg (currently in HttpReply.c @?@ ) */
SQUIDCEXTERN int httpMsgIsolateHeaders(const char **parse_start, const char **blk_start, const char **blk_end);

SQUIDCEXTERN void icmpOpen(void);
SQUIDCEXTERN void icmpClose(void);

SQUIDCEXTERN void icmpSourcePing(struct IN_ADDR to, const icp_common_t *, const char *url);

SQUIDCEXTERN void icmpDomainPing(struct IN_ADDR to, const char *domain);

#ifdef SQUID_SNMP
SQUIDCEXTERN PF snmpHandleUdp;
SQUIDCEXTERN void snmpInit(void);
SQUIDCEXTERN void snmpConnectionOpen(void);
SQUIDCEXTERN void snmpConnectionShutdown(void);
SQUIDCEXTERN void snmpConnectionClose(void);
SQUIDCEXTERN void snmpDebugOid(int lvl, oid * Name, snint Len);

SQUIDCEXTERN void addr2oid(struct IN_ADDR addr, oid * Dest);

SQUIDCEXTERN struct IN_ADDR *oid2addr(oid * id);

SQUIDCEXTERN struct IN_ADDR *client_entry(struct IN_ADDR *current);
SQUIDCEXTERN variable_list *snmp_basicFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_confFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_sysFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_prfSysFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_prfProtoFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_prfPeerFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_netIpFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_netFqdnFn(variable_list *, snint *);
#if USE_DNSSERVERS
SQUIDCEXTERN variable_list *snmp_netDnsFn(variable_list *, snint *);
#else
SQUIDCEXTERN variable_list *snmp_netIdnsFn(variable_list *, snint *);
#endif
SQUIDCEXTERN variable_list *snmp_meshPtblFn(variable_list *, snint *);
SQUIDCEXTERN variable_list *snmp_meshCtblFn(variable_list *, snint *);
#endif /* SQUID_SNMP */

#if USE_WCCP
SQUIDCEXTERN void wccpInit(void);
SQUIDCEXTERN void wccpConnectionOpen(void);
SQUIDCEXTERN void wccpConnectionShutdown(void);
SQUIDCEXTERN void wccpConnectionClose(void);
#endif /* USE_WCCP */

SQUIDCEXTERN void ipcache_nbgethostbyname(const char *name,
        IPH * handler,
        void *handlerData);
SQUIDCEXTERN EVH ipcache_purgelru;
SQUIDCEXTERN const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
SQUIDCEXTERN void ipcacheInvalidate(const char *);
SQUIDCEXTERN void ipcacheInvalidateNegative(const char *);
SQUIDCEXTERN void ipcache_init(void);
SQUIDCEXTERN void stat_ipcache_get(StoreEntry *);
SQUIDCEXTERN void ipcacheCycleAddr(const char *name, ipcache_addrs *);

SQUIDCEXTERN void ipcacheMarkBadAddr(const char *name, struct IN_ADDR);

SQUIDCEXTERN void ipcacheMarkGoodAddr(const char *name, struct IN_ADDR);
SQUIDCEXTERN void ipcacheFreeMemory(void);
SQUIDCEXTERN ipcache_addrs *ipcacheCheckNumeric(const char *name);
SQUIDCEXTERN void ipcache_restart(void);
SQUIDCEXTERN int ipcacheAddEntryFromHosts(const char *name, const char *ipaddr);

SQUIDCEXTERN char *mime_get_header(const char *mime, const char *header);
SQUIDCEXTERN char *mime_get_header_field(const char *mime, const char *name, const char *prefix);
SQUIDCEXTERN size_t headersEnd(const char *, size_t);
SQUIDCEXTERN const char *mime_get_auth(const char *hdr, const char *auth_scheme, const char **auth_field);

SQUIDCEXTERN void mimeInit(char *filename);
SQUIDCEXTERN void mimeFreeMemory(void);
SQUIDCEXTERN char *mimeGetContentEncoding(const char *fn);
SQUIDCEXTERN char *mimeGetContentType(const char *fn);
SQUIDCEXTERN char const *mimeGetIcon(const char *fn);
SQUIDCEXTERN const char *mimeGetIconURL(const char *fn);
SQUIDCEXTERN char mimeGetTransferMode(const char *fn);
SQUIDCEXTERN int mimeGetDownloadOption(const char *fn);
SQUIDCEXTERN int mimeGetViewOption(const char *fn);

SQUIDCEXTERN int mcastSetTtl(int, int);
SQUIDCEXTERN IPH mcastJoinGroups;

/* Labels for hierachical log file */
/* put them all here for easier reference when writing a logfile analyzer */


SQUIDCEXTERN peer *getFirstPeer(void);
SQUIDCEXTERN peer *getFirstUpParent(HttpRequest *);
SQUIDCEXTERN peer *getNextPeer(peer *);
SQUIDCEXTERN peer *getSingleParent(HttpRequest *);
SQUIDCEXTERN int neighborsCount(HttpRequest *);
SQUIDCEXTERN int neighborsUdpPing(HttpRequest *,
                                  StoreEntry *,
                                  IRCB * callback,
                                  void *data,
                                  int *exprep,
                                  int *timeout);
SQUIDCEXTERN void neighborAddAcl(const char *, const char *);

SQUIDCEXTERN void neighborsUdpAck(const cache_key *, icp_common_t *, const struct sockaddr_in *);
SQUIDCEXTERN void neighborAdd(const char *, const char *, int, int, int, int, int);
SQUIDCEXTERN void neighbors_init(void);
SQUIDCEXTERN peer *peerFindByName(const char *);
SQUIDCEXTERN peer *peerFindByNameAndPort(const char *, unsigned short);
SQUIDCEXTERN peer *getDefaultParent(HttpRequest * request);
SQUIDCEXTERN peer *getRoundRobinParent(HttpRequest * request);
SQUIDCEXTERN peer *getWeightedRoundRobinParent(HttpRequest * request);
SQUIDCEXTERN EVH peerClearRR;
SQUIDCEXTERN peer *getAnyParent(HttpRequest * request);
SQUIDCEXTERN lookup_t peerDigestLookup(peer * p, HttpRequest * request);
SQUIDCEXTERN peer *neighborsDigestSelect(HttpRequest * request);
SQUIDCEXTERN void peerNoteDigestLookup(HttpRequest * request, peer * p, lookup_t lookup);
SQUIDCEXTERN void peerNoteDigestGone(peer * p);
SQUIDCEXTERN int neighborUp(const peer * e);
SQUIDCEXTERN CBDUNL peerDestroy;
SQUIDCEXTERN const char *neighborTypeStr(const peer * e);
SQUIDCEXTERN peer_t neighborType(const peer *, const HttpRequest *);
SQUIDCEXTERN void peerConnectFailed(peer *);
SQUIDCEXTERN void peerConnectSucceded(peer *);
SQUIDCEXTERN void dump_peer_options(StoreEntry *, peer *);
SQUIDCEXTERN int peerHTTPOkay(const peer *, HttpRequest *);

SQUIDCEXTERN peer *whichPeer(const struct sockaddr_in *from);

SQUIDCEXTERN void netdbInit(void);

SQUIDCEXTERN void netdbHandlePingReply(const struct sockaddr_in *from, int hops, int rtt);
SQUIDCEXTERN void netdbPingSite(const char *hostname);
SQUIDCEXTERN void netdbDump(StoreEntry *);

SQUIDCEXTERN int netdbHops(struct IN_ADDR);
SQUIDCEXTERN void netdbFreeMemory(void);
SQUIDCEXTERN int netdbHostHops(const char *host);
SQUIDCEXTERN int netdbHostRtt(const char *host);
SQUIDCEXTERN void netdbUpdatePeer(HttpRequest *, peer * e, int rtt, int hops);

SQUIDCEXTERN void netdbDeleteAddrNetwork(struct IN_ADDR addr);
SQUIDCEXTERN void netdbBinaryExchange(StoreEntry *);
SQUIDCEXTERN EVH netdbExchangeStart;

SQUIDCEXTERN void netdbExchangeUpdatePeer(struct IN_ADDR, peer *, double, double);
SQUIDCEXTERN peer *netdbClosestParent(HttpRequest *);
SQUIDCEXTERN void netdbHostData(const char *host, int *samp, int *rtt, int *hops);

SQUIDCEXTERN void cachemgrStart(int fd, HttpRequest * request, StoreEntry * entry);
SQUIDCEXTERN void cachemgrRegister(const char *, const char *, OBJH *, int, int);
SQUIDCEXTERN void cachemgrInit(void);

SQUIDCEXTERN void peerSelect(HttpRequest *, StoreEntry *, PSC *, void *data);
SQUIDCEXTERN void peerSelectInit(void);

/* peer_digest.c */
SQUIDCEXTERN PeerDigest *peerDigestCreate(peer * p);
SQUIDCEXTERN void peerDigestNeeded(PeerDigest * pd);
SQUIDCEXTERN void peerDigestNotePeerGone(PeerDigest * pd);
SQUIDCEXTERN void peerDigestStatsReport(const PeerDigest * pd, StoreEntry * e);

/* forward.c */
SQUIDCEXTERN void fwdStart(int, StoreEntry *, HttpRequest *);
SQUIDCEXTERN void fwdFail(FwdState *, ErrorState *);
SQUIDCEXTERN void fwdUnregister(int fd, FwdState *);
SQUIDCEXTERN void fwdComplete(FwdState * fwdState);
SQUIDCEXTERN void fwdInit(void);
SQUIDCEXTERN int fwdReforwardableStatus(http_status s);
SQUIDCEXTERN void fwdServersFree(FwdServer ** FSVR);
#if WIP_FWD_LOG
SQUIDCEXTERN void fwdUninit(void);
SQUIDCEXTERN void fwdLogRotate(void);
SQUIDCEXTERN void fwdStatus(FwdState *, http_status);
#endif

SQUIDCEXTERN struct IN_ADDR getOutgoingAddr(HttpRequest * request);
unsigned long getOutgoingTOS(HttpRequest * request);

SQUIDCEXTERN void urnStart(HttpRequest *, StoreEntry *);

SQUIDCEXTERN void redirectInit(void);
SQUIDCEXTERN void redirectShutdown(void);

extern void refreshAddToList(const char *, int, time_t, int, time_t);
extern int refreshIsCachable(const StoreEntry *);
extern int refreshCheckHTTP(const StoreEntry *, HttpRequest *);
extern int refreshCheckICP(const StoreEntry *, HttpRequest *);
extern int refreshCheckHTCP(const StoreEntry *, HttpRequest *);
extern int refreshCheckDigest(const StoreEntry *, time_t delta);
extern time_t getMaxAge(const char *url);
extern void refreshInit(void);
extern const refresh_t *refreshLimits(const char *url);

extern void serverConnectionsClose(void);
extern void shut_down(int);
extern void rotate_logs(int);
extern void reconfigure(int);


extern void start_announce(void *unused);
extern void waisStart(FwdState *);

/* ident.c */
#if USE_IDENT

SQUIDCEXTERN void identStart(struct sockaddr_in *me, struct sockaddr_in *my_peer,
                             IDCB * callback, void *cbdata);
SQUIDCEXTERN void identInit(void);
#endif

SQUIDCEXTERN void statInit(void);
SQUIDCEXTERN void statFreeMemory(void);
SQUIDCEXTERN double median_svc_get(int, int);
SQUIDCEXTERN void pconnHistCount(int, int);
SQUIDCEXTERN int stat5minClientRequests(void);
SQUIDCEXTERN double stat5minCPUUsage(void);
SQUIDCEXTERN double statRequestHitRatio(int minutes);
SQUIDCEXTERN double statRequestHitMemoryRatio(int minutes);
SQUIDCEXTERN double statRequestHitDiskRatio(int minutes);
SQUIDCEXTERN double statByteHitRatio(int minutes);

/* StatHist */
SQUIDCEXTERN void statHistClean(StatHist * H);
SQUIDCEXTERN void statHistCount(StatHist * H, double val);
SQUIDCEXTERN void statHistCopy(StatHist * Dest, const StatHist * Orig);
SQUIDCEXTERN void statHistSafeCopy(StatHist * Dest, const StatHist * Orig);
SQUIDCEXTERN double statHistDeltaMedian(const StatHist * A, const StatHist * B);
SQUIDCEXTERN void statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper * bd);
SQUIDCEXTERN void statHistLogInit(StatHist * H, int capacity, double min, double max);
SQUIDCEXTERN void statHistEnumInit(StatHist * H, int last_enum);
SQUIDCEXTERN void statHistIntInit(StatHist * H, int n);
SQUIDCEXTERN StatHistBinDumper statHistEnumDumper;
SQUIDCEXTERN StatHistBinDumper statHistIntDumper;


/* mem */
SQUIDCEXTERN void memClean(void);
SQUIDCEXTERN void memInitModule(void);
SQUIDCEXTERN void memCleanModule(void);
SQUIDCEXTERN void memConfigure(void);
SQUIDCEXTERN void *memAllocate(mem_type);
SQUIDCEXTERN void *memAllocString(size_t net_size, size_t * gross_size);
SQUIDCEXTERN void *memAllocBuf(size_t net_size, size_t * gross_size);
SQUIDCEXTERN void *memReallocBuf(void *buf, size_t net_size, size_t * gross_size);
SQUIDCEXTERN void memFree(void *, int type);
SQUIDCEXTERN void memFree4K(void *);
SQUIDCEXTERN void memFree8K(void *);
SQUIDCEXTERN void memFreeString(size_t size, void *);
SQUIDCEXTERN void memFreeBuf(size_t size, void *);
SQUIDCEXTERN FREE *memFreeBufFunc(size_t size);
SQUIDCEXTERN int memInUse(mem_type);
SQUIDCEXTERN void memDataInit(mem_type, const char *, size_t, int);
SQUIDCEXTERN void memCheckInit(void);


/* Mem */
SQUIDCEXTERN void memConfigure(void);

/* ----------------------------------------------------------------- */

/* repl_modules.c */
SQUIDCEXTERN void storeReplSetup(void);

/* store_io.c */
#include "StoreIOState.h"
extern StoreIOState::Pointer storeCreate(StoreEntry *, STFNCB *, STIOCB *, void *);
extern StoreIOState::Pointer storeOpen(StoreEntry *, STFNCB *, STIOCB *, void *);
SQUIDCEXTERN void storeClose(StoreIOState::Pointer);
SQUIDCEXTERN void storeRead(StoreIOState::Pointer, char *, size_t, off_t, STRCB *, void *);
SQUIDCEXTERN void storeIOWrite(StoreIOState::Pointer, char const *, size_t, off_t, FREE *);

/*
 * store_log.c
 */
SQUIDCEXTERN void storeLog(int tag, const StoreEntry * e);
SQUIDCEXTERN void storeLogRotate(void);
SQUIDCEXTERN void storeLogClose(void);
SQUIDCEXTERN void storeLogOpen(void);


/*
 * store_key_*.c
 */
SQUIDCEXTERN cache_key *storeKeyDup(const cache_key *);
SQUIDCEXTERN cache_key *storeKeyCopy(cache_key *, const cache_key *);
SQUIDCEXTERN void storeKeyFree(const cache_key *);
SQUIDCEXTERN const cache_key *storeKeyScan(const char *);
SQUIDCEXTERN const char *storeKeyText(const cache_key *);
SQUIDCEXTERN const cache_key *storeKeyPublic(const char *, const method_t);
SQUIDCEXTERN const cache_key *storeKeyPublicByRequest(HttpRequest *);
SQUIDCEXTERN const cache_key *storeKeyPublicByRequestMethod(HttpRequest *, const method_t);
SQUIDCEXTERN const cache_key *storeKeyPrivate(const char *, method_t, int);
SQUIDCEXTERN int storeKeyHashBuckets(int);
SQUIDCEXTERN int storeKeyNull(const cache_key *);
SQUIDCEXTERN void storeKeyInit(void);
SQUIDCEXTERN HASHHASH storeKeyHashHash;
SQUIDCEXTERN HASHCMP storeKeyHashCmp;

/*
 * store_digest.c
 */
SQUIDCEXTERN void storeDigestInit(void);
SQUIDCEXTERN void storeDigestNoteStoreReady(void);
SQUIDCEXTERN void storeDigestScheduleRebuild(void);
SQUIDCEXTERN void storeDigestDel(const StoreEntry * entry);
SQUIDCEXTERN void storeDigestReport(StoreEntry *);

/*
 * store_rebuild.c
 */
SQUIDCEXTERN void storeRebuildStart(void);

SQUIDCEXTERN void storeRebuildComplete(struct _store_rebuild_data *);
SQUIDCEXTERN void storeRebuildProgress(int sd_index, int total, int sofar);

/*
 * store_swapin.c
 */
SQUIDCEXTERN void storeSwapInStart(store_client *);

/*
 * store_swapout.c
 */
SQUIDCEXTERN void storeSwapOut(StoreEntry * e);
SQUIDCEXTERN void storeSwapOutFileClose(StoreEntry * e);
SQUIDCEXTERN int storeSwapOutAble(const StoreEntry * e);

/*
 * store_client.c
 */
SQUIDCEXTERN store_client *storeClientListAdd(StoreEntry * e, void *data);
SQUIDCEXTERN int storeClientCopyPending(store_client *, StoreEntry * e, void *data);
SQUIDCEXTERN int storeUnregister(store_client * sc, StoreEntry * e, void *data);
SQUIDCEXTERN void InvokeHandlers(StoreEntry * e);
SQUIDCEXTERN int storePendingNClients(const StoreEntry * e);
SQUIDCEXTERN int storeClientIsThisAClient(store_client * sc, void *someClient);


SQUIDCEXTERN const char *getMyHostname(void);
SQUIDCEXTERN const char *uniqueHostname(void);
SQUIDCEXTERN void safeunlink(const char *path, int quiet);
SQUIDCEXTERN void death(int sig);
SQUIDCEXTERN void fatal(const char *message);
#if STDC_HEADERS
SQUIDCEXTERN void
fatalf(const char *fmt,...) PRINTF_FORMAT_ARG1;
#else
SQUIDCEXTERN void fatalf();
#endif
SQUIDCEXTERN void fatal_dump(const char *message);
SQUIDCEXTERN void sigusr2_handle(int sig);
SQUIDCEXTERN void sig_child(int sig);
SQUIDCEXTERN void leave_suid(void);
SQUIDCEXTERN void enter_suid(void);
SQUIDCEXTERN void no_suid(void);
SQUIDCEXTERN void writePidFile(void);
SQUIDCEXTERN void setSocketShutdownLifetimes(int);
SQUIDCEXTERN void setMaxFD(void);
SQUIDCEXTERN time_t getCurrentTime(void);
SQUIDCEXTERN int percent(int, int);
SQUIDCEXTERN double dpercent(double, double);
SQUIDCEXTERN void squid_signal(int sig, SIGHDLR *, int flags);
SQUIDCEXTERN pid_t readPidFile(void);

SQUIDCEXTERN struct IN_ADDR inaddrFromHostent(const struct hostent *hp);
SQUIDCEXTERN int intAverage(int, int, int, int);
SQUIDCEXTERN double doubleAverage(double, double, int, int);
SQUIDCEXTERN void debug_trap(const char *);
SQUIDCEXTERN void logsFlush(void);
SQUIDCEXTERN const char *checkNullString(const char *p);

SQUIDCEXTERN void squid_getrusage(struct rusage *r);

SQUIDCEXTERN double rusage_cputime(struct rusage *r);

SQUIDCEXTERN int rusage_maxrss(struct rusage *r);

SQUIDCEXTERN int rusage_pagefaults(struct rusage *r);
SQUIDCEXTERN void releaseServerSockets(void);
SQUIDCEXTERN void PrintRusage(void);
SQUIDCEXTERN void dumpMallocStats(void);

#if USE_UNLINKD
SQUIDCEXTERN void unlinkdInit(void);
SQUIDCEXTERN void unlinkdClose(void);
SQUIDCEXTERN void unlinkdUnlink(const char *);
#endif

SQUIDCEXTERN char *url_convert_hex(char *org_url, int allocate);
SQUIDCEXTERN char *url_escape(const char *url);
SQUIDCEXTERN protocol_t urlParseProtocol(const char *);
SQUIDCEXTERN method_t urlParseMethod(const char *);
SQUIDCEXTERN void urlInitialize(void);
SQUIDCEXTERN HttpRequest *urlParse(method_t, char *);
SQUIDCEXTERN const char *urlCanonical(HttpRequest *);
SQUIDCEXTERN char *urlRInternal(const char *host, u_short port, const char *dir, const char *name);
SQUIDCEXTERN char *urlInternal(const char *dir, const char *name);
SQUIDCEXTERN int matchDomainName(const char *host, const char *domain);
SQUIDCEXTERN int urlCheckRequest(const HttpRequest *);
SQUIDCEXTERN int urlDefaultPort(protocol_t p);
SQUIDCEXTERN char *urlCanonicalClean(const HttpRequest *);
SQUIDCEXTERN char *urlHostname(const char *url);
SQUIDCEXTERN void urlExtMethodConfigure(void);

SQUIDCEXTERN void useragentOpenLog(void);
SQUIDCEXTERN void useragentRotateLog(void);
SQUIDCEXTERN void logUserAgent(const char *, const char *);
SQUIDCEXTERN void useragentLogClose(void);
SQUIDCEXTERN void refererOpenLog(void);
SQUIDCEXTERN void refererRotateLog(void);
SQUIDCEXTERN void logReferer(const char *, const char *, const char *);
SQUIDCEXTERN void refererCloseLog(void);
SQUIDCEXTERN peer_t parseNeighborType(const char *s);

SQUIDCEXTERN void errorInitialize(void);
SQUIDCEXTERN void errorClean(void);
SQUIDCEXTERN HttpReply *errorBuildReply(ErrorState * err);
SQUIDCEXTERN void errorSend(int fd, ErrorState *);
SQUIDCEXTERN void errorAppendEntry(StoreEntry *, ErrorState *);
SQUIDCEXTERN void errorStateFree(ErrorState * err);
SQUIDCEXTERN err_type errorReservePageId(const char *page_name);
SQUIDCEXTERN ErrorState *errorCon(err_type type, http_status);

SQUIDCEXTERN void pconnPush(int, const char *host, u_short port, const char *domain);
SQUIDCEXTERN int pconnPop(const char *host, u_short port, const char *domain);
SQUIDCEXTERN void pconnInit(void);

/* tools.c */
SQUIDCEXTERN void dlinkAdd(void *data, dlink_node *, dlink_list *);
SQUIDCEXTERN void dlinkAddAfter(void *, dlink_node *, dlink_node *, dlink_list *);
SQUIDCEXTERN void dlinkAddTail(void *data, dlink_node *, dlink_list *);
SQUIDCEXTERN void dlinkDelete(dlink_node * m, dlink_list * list);
SQUIDCEXTERN void dlinkNodeDelete(dlink_node * m);
SQUIDCEXTERN dlink_node *dlinkNodeNew(void);

SQUIDCEXTERN void kb_incr(kb_t *, size_t);
SQUIDCEXTERN int stringHasWhitespace(const char *);
SQUIDCEXTERN int stringHasCntl(const char *);
SQUIDCEXTERN void linklistPush(link_list **, void *);
SQUIDCEXTERN void *linklistShift(link_list **);
SQUIDCEXTERN int xrename(const char *from, const char *to);
SQUIDCEXTERN int isPowTen(int);
SQUIDCEXTERN void parseEtcHosts(void);
SQUIDCEXTERN int getMyPort(void);

SQUIDCEXTERN char *strwordtok(char *buf, char **t);
SQUIDCEXTERN void strwordquote(MemBuf * mb, const char *str);



/*
 * ipc.c
 */
SQUIDCEXTERN int ipcCreate(int type,
                           const char *prog,
                           const char *const args[],
                           const char *name,
                           int *rfd,
                           int *wfd);

/* CacheDigest */
SQUIDCEXTERN CacheDigest *cacheDigestCreate(int capacity, int bpe);
SQUIDCEXTERN void cacheDigestDestroy(CacheDigest * cd);
SQUIDCEXTERN CacheDigest *cacheDigestClone(const CacheDigest * cd);
SQUIDCEXTERN void cacheDigestClear(CacheDigest * cd);
SQUIDCEXTERN void cacheDigestChangeCap(CacheDigest * cd, int new_cap);
SQUIDCEXTERN int cacheDigestTest(const CacheDigest * cd, const cache_key * key);
SQUIDCEXTERN void cacheDigestAdd(CacheDigest * cd, const cache_key * key);
SQUIDCEXTERN void cacheDigestDel(CacheDigest * cd, const cache_key * key);
SQUIDCEXTERN size_t cacheDigestCalcMaskSize(int cap, int bpe);
SQUIDCEXTERN int cacheDigestBitUtil(const CacheDigest * cd);
SQUIDCEXTERN void cacheDigestGuessStatsUpdate(cd_guess_stats * stats, int real_hit, int guess_hit);
SQUIDCEXTERN void cacheDigestGuessStatsReport(const cd_guess_stats * stats, StoreEntry * sentry, const char *label);
SQUIDCEXTERN void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

SQUIDCEXTERN void internalStart(HttpRequest *, StoreEntry *);
SQUIDCEXTERN int internalCheck(const char *urlpath);
SQUIDCEXTERN int internalStaticCheck(const char *urlpath);
SQUIDCEXTERN char *internalLocalUri(const char *dir, const char *name);
SQUIDCEXTERN char *internalRemoteUri(const char *, u_short, const char *, const char *);
SQUIDCEXTERN const char *internalHostname(void);
SQUIDCEXTERN int internalHostnameIs(const char *);

#if USE_CARP
SQUIDCEXTERN void carpInit(void);
SQUIDCEXTERN peer *carpSelectParent(HttpRequest *);
#endif

/* helper.c */
SQUIDCEXTERN void helperOpenServers(helper * hlp);
SQUIDCEXTERN void helperStatefulOpenServers(statefulhelper * hlp);
SQUIDCEXTERN void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
SQUIDCEXTERN void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver);
SQUIDCEXTERN void helperStats(StoreEntry * sentry, helper * hlp);
SQUIDCEXTERN void helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp);
SQUIDCEXTERN void helperShutdown(helper * hlp);
SQUIDCEXTERN void helperStatefulShutdown(statefulhelper * hlp);
SQUIDCEXTERN helper *helperCreate(const char *);
SQUIDCEXTERN statefulhelper *helperStatefulCreate(const char *);
SQUIDCEXTERN void helperFree(helper *);
SQUIDCEXTERN void helperStatefulFree(statefulhelper *);
SQUIDCEXTERN void helperStatefulReset(helper_stateful_server * srv);
SQUIDCEXTERN void helperStatefulReleaseServer(helper_stateful_server * srv);
SQUIDCEXTERN void *helperStatefulServerGetData(helper_stateful_server * srv);
SQUIDCEXTERN helper_stateful_server *helperStatefulDefer(statefulhelper *);



#if USE_LEAKFINDER
SQUIDCEXTERN void leakInit(void);
SQUIDCEXTERN void *leakAddFL(void *, const char *, int);
SQUIDCEXTERN void *leakTouchFL(void *, const char *, int);
SQUIDCEXTERN void *leakFreeFL(void *, const char *, int);
#endif

/* logfile.c */
SQUIDCEXTERN Logfile *logfileOpen(const char *path, size_t bufsz, int);
SQUIDCEXTERN void logfileClose(Logfile * lf);
SQUIDCEXTERN void logfileRotate(Logfile * lf);
SQUIDCEXTERN void logfileWrite(Logfile * lf, void *buf, size_t len);
SQUIDCEXTERN void logfileFlush(Logfile * lf);
#if STDC_HEADERS
SQUIDCEXTERN void
logfilePrintf(Logfile * lf, const char *fmt,...) PRINTF_FORMAT_ARG2;
#else
SQUIDCEXTERN void logfilePrintf(va_alist);
#endif

/*
 * Removal Policies
 */
SQUIDCEXTERN RemovalPolicy *createRemovalPolicy(RemovalPolicySettings * settings);

/*
 * prototypes for system functions missing from system includes
 */

#ifdef _SQUID_SOLARIS_

SQUIDCEXTERN int getrusage(int, struct rusage *);
SQUIDCEXTERN int getpagesize(void);
#if !defined(_XPG4_2) && !(defined(__EXTENSIONS__) || \
        (!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)))
SQUIDCEXTERN int gethostname(char *, int);
#endif
#endif

/*
 * hack to allow snmp access to the statistics counters
 */
SQUIDCEXTERN StatCounters *snmpStatGet(int);

/* Vary support functions */
SQUIDCEXTERN int varyEvaluateMatch(StoreEntry * entry, HttpRequest * req);

/* CygWin & Windows NT Port */
/* win32.c */
#ifdef _SQUID_WIN32_
#ifdef USE_WIN32_SERVICE
SQUIDCEXTERN int WIN32_Subsystem_Init(int *, char ***);
#else
SQUIDCEXTERN int WIN32_Subsystem_Init(void);
#endif
SQUIDCEXTERN void WIN32_sendSignal(int);
SQUIDCEXTERN void WIN32_Abort(int);
SQUIDCEXTERN void WIN32_Exit(void);
SQUIDCEXTERN void WIN32_SetServiceCommandLine(void);
SQUIDCEXTERN void WIN32_InstallService(void);
SQUIDCEXTERN void WIN32_RemoveService(void);
#endif /* _SQUID_WIN32_ */
#ifdef _SQUID_MSWIN_

SQUIDCEXTERN int WIN32_getrusage(int, struct rusage *);
#endif

/* external_acl.c */
SQUIDCEXTERN void parse_externalAclHelper(external_acl **);
SQUIDCEXTERN void dump_externalAclHelper(StoreEntry * sentry, const char *name, const external_acl *);
SQUIDCEXTERN void free_externalAclHelper(external_acl **);
typedef void EAH(void *data, void *result);
SQUIDCEXTERN void externalAclLookup(ACLChecklist * ch, void *acl_data, EAH * handler, void *data);
SQUIDCEXTERN void externalAclInit(void);
SQUIDCEXTERN void externalAclShutdown(void);
SQUIDCEXTERN char *strtokFile(void);

#endif /* SQUID_PROTOS_H */
