
/*
 * $Id: protos.h,v 1.435 2002/04/14 21:51:36 hno Exp $
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

extern void accessLogLog(AccessLogEntry *);
extern void accessLogRotate(void);
extern void accessLogClose(void);
extern void accessLogInit(void);
extern const char *accessLogTime(time_t);
extern void hierarchyNote(HierarchyLogEntry *, hier_code, const char *);
#if FORW_VIA_DB
extern void fvdbCountVia(const char *key);
extern void fvdbCountForw(const char *key);
#endif
#if HEADERS_LOG
extern void headersLog(int cs, int pq, method_t m, void *data);
#endif
char *log_quote(const char *header);

/* acl.c */
extern aclCheck_t *aclChecklistCreate(const struct _acl_access *,
    request_t *,
    const char *ident);
extern void aclNBCheck(aclCheck_t *, PF *, void *);
extern int aclCheckFast(const struct _acl_access *A, aclCheck_t *);
extern void aclChecklistFree(aclCheck_t *);
extern int aclMatchAclList(const acl_list * list, aclCheck_t * checklist);
extern void aclDestroyAccessList(struct _acl_access **list);
extern void aclDestroyAcls(acl **);
extern void aclDestroyAclList(acl_list **);
extern void aclParseAccessLine(struct _acl_access **);
extern void aclParseAclList(acl_list **);
extern void aclParseAclLine(acl **);
extern int aclIsProxyAuth(const char *name);
extern err_type aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name);
extern void aclParseDenyInfoLine(struct _acl_deny_info_list **);
extern void aclDestroyDenyInfoList(struct _acl_deny_info_list **);
extern void aclDestroyRegexList(struct _relist *data);
extern int aclMatchRegex(relist * data, const char *word);
extern void aclParseRegexList(void *curlist);
extern const char *aclTypeToStr(squid_acl);
extern wordlist *aclDumpGeneric(const acl *);
extern int aclPurgeMethodInUse(acl_access *);
extern void aclCacheMatchFlush(dlink_list * cache);

/*
 * cache_cf.c
 */
extern int parseConfigFile(const char *file_name);
extern void intlistDestroy(intlist **);
extern int intlistFind(intlist * list, int i);
extern const char *wordlistAdd(wordlist **, const char *);
extern void wordlistAddWl(wordlist **, wordlist *);
extern void wordlistJoin(wordlist **, wordlist **);
extern wordlist *wordlistDup(const wordlist *);
extern void wordlistDestroy(wordlist **);
extern void configFreeMemory(void);
extern void wordlistCat(const wordlist *, MemBuf * mb);
extern void allocate_new_swapdir(cacheSwap *);
extern void self_destruct(void);
extern int GetInteger(void);

/* extra functions from cache_cf.c useful for lib modules */
extern void parse_int(int *var);
extern void parse_onoff(int *var);
extern void parse_eol(char *volatile *var);
extern void parse_wordlist(wordlist ** list);
extern void requirePathnameExists(const char *name, const char *path);
extern void parse_time_t(time_t * var);
extern void parse_cachedir_options(SwapDir * sd, struct cache_dir_option *options, int reconfiguring);
extern void dump_cachedir_options(StoreEntry * e, struct cache_dir_option *options, SwapDir * sd);
extern void parse_sockaddr_in_list_token(sockaddr_in_list **, char *);


/*
 * cbdata.c
 */
extern void cbdataInit(void);
#if CBDATA_DEBUG
extern void *cbdataInternalAllocDbg(cbdata_type type, const char *, int);
extern void *cbdataInternalFreeDbg(void *p, const char *, int);
extern void cbdataInternalLockDbg(const void *p, const char *, int);
extern void cbdataInternalUnlockDbg(const void *p, const char *, int);
extern int cbdataInternalReferenceDoneValidDbg(void **p, void **tp, const char *, int);
#else
extern void *cbdataInternalAlloc(cbdata_type type);
extern void *cbdataInternalFree(void *p);
extern void cbdataInternalLock(const void *p);
extern void cbdataInternalUnlock(const void *p);
extern int cbdataInternalReferenceDoneValid(void **p, void **tp);
#endif
extern int cbdataReferenceValid(const void *p);
extern cbdata_type cbdataInternalAddType(cbdata_type type, const char *label, int size, FREE * free_func);

extern void clientdbInit(void);
extern void clientdbUpdate(struct in_addr, log_type, protocol_t, size_t);
extern int clientdbCutoffDenied(struct in_addr);
extern void clientdbDump(StoreEntry *);
extern void clientdbFreeMemory(void);
extern int clientdbEstablished(struct in_addr, int);

extern void clientAccessCheck(void *);
extern void clientAccessCheckDone(int, void *);
extern int modifiedSince(StoreEntry *, request_t *);
extern char *clientConstructTraceEcho(clientHttpRequest *);
extern void clientPurgeRequest(clientHttpRequest *);
extern int checkNegativeHit(StoreEntry *);
extern void clientOpenListenSockets(void);
extern void clientHttpConnectionsClose(void);
extern StoreEntry *clientCreateStoreEntry(clientHttpRequest *, method_t, request_flags);
extern int isTcpHit(log_type);
extern void clientReadBody(request_t * req, char *buf, size_t size, CBCB * callback, void *data);
extern int clientAbortBody(request_t * req);

extern int commSetNonBlocking(int fd);
extern int commUnsetNonBlocking(int fd);
extern void commSetCloseOnExec(int fd);
extern int comm_accept(int fd, struct sockaddr_in *, struct sockaddr_in *);
extern void comm_close(int fd);
extern void comm_reset_close(int fd);
#if LINGERING_CLOSE
extern void comm_lingering_close(int fd);
#endif
extern void commConnectStart(int fd, const char *, u_short, CNCB *, void *);
extern int comm_connect_addr(int sock, const struct sockaddr_in *);
extern void comm_init(void);
extern int comm_listen(int sock);
extern int comm_open(int, int, struct in_addr, u_short port, int, const char *note);
extern int comm_openex(int, int, struct in_addr, u_short, int, unsigned char TOS, const char *);
extern u_short comm_local_port(int fd);

extern void commSetSelect(int, unsigned int, PF *, void *, time_t);
extern void comm_add_close_handler(int fd, PF *, void *);
extern void comm_remove_close_handler(int fd, PF *, void *);
extern int comm_udp_sendto(int, const struct sockaddr_in *, int, const void *, int);
extern void comm_write(int fd,
    const char *buf,
    int size,
    CWCB * handler,
    void *handler_data,
    FREE *);
extern void comm_write_mbuf(int fd, MemBuf mb, CWCB * handler, void *handler_data);
extern void commCallCloseHandlers(int fd);
extern int commSetTimeout(int fd, int, PF *, void *);
extern void commSetDefer(int fd, DEFER * func, void *);
extern int ignoreErrno(int);
extern void commCloseAllSockets(void);
extern void checkTimeouts(void);
extern int commDeferRead(int fd);


/*
 * comm_select.c
 */
extern void comm_select_init(void);
extern int comm_select(int);
extern void comm_quick_poll_required(void);

extern void packerToStoreInit(Packer * p, StoreEntry * e);
extern void packerToMemInit(Packer * p, MemBuf * mb);
extern void packerClean(Packer * p);
extern void packerAppend(Packer * p, const char *buf, int size);
#if STDC_HEADERS
extern void
packerPrintf(Packer * p, const char *fmt,...) PRINTF_FORMAT_ARG2;
#else
extern void packerPrintf();
#endif


/* see debug.c for info on context-based debugging */
extern Ctx ctx_enter(const char *descr);
extern void ctx_exit(Ctx ctx);

extern void _db_init(const char *logfile, const char *options);
extern void _db_rotate_log(void);

#if STDC_HEADERS
extern void
_db_print(const char *,...) PRINTF_FORMAT_ARG1;
#else
extern void _db_print();
#endif
extern void xassert(const char *, const char *, int);

/* packs, then prints an object using debug() */
extern void debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm);

/* disk.c */
extern int file_open(const char *path, int mode);
extern void file_close(int fd);
extern void file_write(int, off_t, void *, int len, DWCB *, void *, FREE *);
extern void file_write_mbuf(int fd, off_t, MemBuf mb, DWCB * handler, void *handler_data);
extern void file_read(int, char *, int, off_t, DRCB *, void *);
extern void disk_init(void);

/* diskd.c */
extern diskd_queue *afile_create_queue(void);
extern void afile_destroy_queue(diskd_queue *);
extern void afile_sync_queue(diskd_queue *);
extern void afile_sync(void);
extern void afile_open(const char *path, int mode, DOCB *, void *);
extern void afile_close(int fd, DCCB * callback, void *data);
extern void afile_write(int, off_t, void *, int len, DWCB *, void *, FREE *);
extern void afile_write_mbuf(int fd, off_t, MemBuf, DWCB *, void *);
extern void afile_read(int, char *, int, off_t, DRCB *, void *);
extern void afile_unlink(const char *path, DUCB *, void *);
extern void afile_truncate(const char *path, DTCB *, void *);

extern void dnsShutdown(void);
extern void dnsInit(void);
extern void dnsSubmit(const char *lookup, HLPCB * callback, void *data);

/* dns_internal.c */
extern void idnsInit(void);
extern void idnsShutdown(void);
extern void idnsALookup(const char *, IDNSCB *, void *);
extern void idnsPTRLookup(const struct in_addr, IDNSCB *, void *);

extern void eventAdd(const char *name, EVH * func, void *arg, double when, int);
extern void eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int);
extern void eventRun(void);
extern time_t eventNextTime(void);
extern void eventDelete(EVH * func, void *arg);
extern void eventInit(void);
extern void eventFreeMemory(void);
extern int eventFind(EVH *, void *);

extern void fd_close(int fd);
extern void fd_open(int fd, unsigned int type, const char *);
extern void fd_note(int fd, const char *);
extern void fd_bytes(int fd, int len, unsigned int type);
extern void fdFreeMemory(void);
extern void fdDumpOpen(void);
extern int fdNFree(void);
extern void fdAdjustReserved(void);

extern fileMap *file_map_create(void);
extern int file_map_allocate(fileMap *, int);
extern int file_map_bit_set(fileMap *, int);
extern int file_map_bit_test(fileMap *, int);
extern void file_map_bit_reset(fileMap *, int);
extern void filemapFreeMemory(fileMap *);


extern void fqdncache_nbgethostbyaddr(struct in_addr, FQDNH *, void *);
extern const char *fqdncache_gethostbyaddr(struct in_addr, int flags);
extern void fqdncache_init(void);
extern void fqdnStats(StoreEntry *);
extern void fqdncacheReleaseInvalid(const char *);
extern const char *fqdnFromAddr(struct in_addr);
extern int fqdncacheQueueDrain(void);
extern void fqdncacheFreeMemory(void);
extern void fqdncache_restart(void);
extern EVH fqdncache_purgelru;
extern void fqdncacheAddEntryFromHosts(char *addr, wordlist * hostnames);

extern void ftpStart(FwdState *);
extern char *ftpUrlWith2f(const request_t *);

extern void gopherStart(FwdState *);
extern int gopherCachable(const char *);


extern void whoisStart(FwdState *);

/* http.c */
extern int httpCachable(method_t);
extern void httpStart(FwdState *);
extern void httpParseReplyHeaders(const char *, http_reply *);
extern void httpProcessReplyHeader(HttpStateData *, const char *, int);
extern mb_size_t httpBuildRequestPrefix(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    MemBuf * mb,
    int cfd,
    http_state_flags);
extern void httpAnonInitModule(void);
extern int httpAnonHdrAllowed(http_hdr_type hdr_id);
extern int httpAnonHdrDenied(http_hdr_type hdr_id);
extern void httpBuildRequestHeader(request_t *, request_t *, StoreEntry *, HttpHeader *, int, http_state_flags);
extern void httpBuildVersion(http_version_t * version, unsigned int major, unsigned int minor);
extern const char *httpMakeVaryMark(request_t * request, HttpReply * reply);

/* ETag */
extern int etagParseInit(ETag * etag, const char *str);
extern int etagIsEqual(const ETag * tag1, const ETag * tag2);

/* Http Status Line */
/* init/clean */
extern void httpStatusLineInit(HttpStatusLine * sline);
extern void httpStatusLineClean(HttpStatusLine * sline);
/* set/get values */
extern void httpStatusLineSet(HttpStatusLine * sline, http_version_t version,
    http_status status, const char *reason);
extern const char *httpStatusLineReason(const HttpStatusLine * sline);
/* parse/pack */
/* parse a 0-terminating buffer and fill internal structires; returns true on success */
extern int httpStatusLineParse(HttpStatusLine * sline, const char *start,
    const char *end);
/* pack fields using Packer */
extern void httpStatusLinePackInto(const HttpStatusLine * sline, Packer * p);
extern const char *httpStatusString(http_status status);

/* Http Body */
/* init/clean */
extern void httpBodyInit(HttpBody * body);
extern void httpBodyClean(HttpBody * body);
/* get body ptr (always use this) */
extern const char *httpBodyPtr(const HttpBody * body);
/* set body, does not clone mb so you should not reuse it */
extern void httpBodySet(HttpBody * body, MemBuf * mb);

/* pack */
extern void httpBodyPackInto(const HttpBody * body, Packer * p);

/* Http Cache Control Header Field */
extern void httpHdrCcInitModule(void);
extern void httpHdrCcCleanModule(void);
extern HttpHdrCc *httpHdrCcCreate(void);
extern HttpHdrCc *httpHdrCcParseCreate(const String * str);
extern void httpHdrCcDestroy(HttpHdrCc * cc);
extern HttpHdrCc *httpHdrCcDup(const HttpHdrCc * cc);
extern void httpHdrCcPackInto(const HttpHdrCc * cc, Packer * p);
extern void httpHdrCcJoinWith(HttpHdrCc * cc, const HttpHdrCc * new_cc);
extern void httpHdrCcSetMaxAge(HttpHdrCc * cc, int max_age);
extern void httpHdrCcSetSMaxAge(HttpHdrCc * cc, int s_maxage);
extern void httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist);
extern void httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);

/* Http Range Header Field */
extern HttpHdrRange *httpHdrRangeParseCreate(const String * range_spec);
/* returns true if ranges are valid; inits HttpHdrRange */
extern int httpHdrRangeParseInit(HttpHdrRange * range, const String * range_spec);
extern void httpHdrRangeDestroy(HttpHdrRange * range);
extern HttpHdrRange *httpHdrRangeDup(const HttpHdrRange * range);
extern void httpHdrRangePackInto(const HttpHdrRange * range, Packer * p);
/* iterate through specs */
extern HttpHdrRangeSpec *httpHdrRangeGetSpec(const HttpHdrRange * range, HttpHdrRangePos * pos);
/* adjust specs after the length is known */
extern int httpHdrRangeCanonize(HttpHdrRange *, ssize_t);
/* other */
extern String httpHdrRangeBoundaryStr(clientHttpRequest * http);
extern int httpHdrRangeIsComplex(const HttpHdrRange * range);
extern int httpHdrRangeWillBeComplex(const HttpHdrRange * range);
extern ssize_t httpHdrRangeFirstOffset(const HttpHdrRange * range);
extern ssize_t httpHdrRangeLowestOffset(const HttpHdrRange * range, ssize_t);
extern int httpHdrRangeOffsetLimit(HttpHdrRange *);


/* Http Content Range Header Field */
extern HttpHdrContRange *httpHdrContRangeCreate(void);
extern HttpHdrContRange *httpHdrContRangeParseCreate(const char *crange_spec);
/* returns true if range is valid; inits HttpHdrContRange */
extern int httpHdrContRangeParseInit(HttpHdrContRange * crange, const char *crange_spec);
extern void httpHdrContRangeDestroy(HttpHdrContRange * crange);
extern HttpHdrContRange *httpHdrContRangeDup(const HttpHdrContRange * crange);
extern void httpHdrContRangePackInto(const HttpHdrContRange * crange, Packer * p);
/* inits with given spec */
extern void httpHdrContRangeSet(HttpHdrContRange *, HttpHdrRangeSpec, ssize_t);

/* Http Header Tools */
extern HttpHeaderFieldInfo *httpHeaderBuildFieldsInfo(const HttpHeaderFieldAttrs * attrs, int count);
extern void httpHeaderDestroyFieldsInfo(HttpHeaderFieldInfo * info, int count);
extern int httpHeaderIdByName(const char *name, int name_len, const HttpHeaderFieldInfo * attrs, int end);
extern int httpHeaderIdByNameDef(const char *name, int name_len);
extern const char *httpHeaderNameById(int id);
extern void httpHeaderMaskInit(HttpHeaderMask * mask, int value);
extern void httpHeaderCalcMask(HttpHeaderMask * mask, const int *enums, int count);
extern int httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive);
extern void httpHeaderAddContRange(HttpHeader *, HttpHdrRangeSpec, ssize_t);
extern void strListAdd(String * str, const char *item, char del);
extern int strListIsMember(const String * str, const char *item, char del);
extern int strListIsSubstr(const String * list, const char *s, char del);
extern int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);
extern const char *getStringPrefix(const char *str, const char *end);
extern int httpHeaderParseInt(const char *start, int *val);
extern int httpHeaderParseSize(const char *start, ssize_t * sz);
extern int httpHeaderReset(HttpHeader * hdr);
#if STDC_HEADERS
extern void
httpHeaderPutStrf(HttpHeader * hdr, http_hdr_type id, const char *fmt,...) PRINTF_FORMAT_ARG3;
#else
extern void httpHeaderPutStrf();
#endif


/* Http Header */
extern void httpHeaderInitModule(void);
extern void httpHeaderCleanModule(void);
/* init/clean */
extern void httpHeaderInit(HttpHeader * hdr, http_hdr_owner_type owner);
extern void httpHeaderClean(HttpHeader * hdr);
/* append/update */
extern void httpHeaderAppend(HttpHeader * dest, const HttpHeader * src);
extern void httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask);
/* parse/pack */
extern int httpHeaderParse(HttpHeader * hdr, const char *header_start, const char *header_end);
extern void httpHeaderPackInto(const HttpHeader * hdr, Packer * p);
/* field manipulation */
extern int httpHeaderHas(const HttpHeader * hdr, http_hdr_type type);
extern void httpHeaderPutInt(HttpHeader * hdr, http_hdr_type type, int number);
extern void httpHeaderPutTime(HttpHeader * hdr, http_hdr_type type, time_t htime);
extern void httpHeaderPutStr(HttpHeader * hdr, http_hdr_type type, const char *str);
extern void httpHeaderPutAuth(HttpHeader * hdr, const char *auth_scheme, const char *realm);
extern void httpHeaderPutCc(HttpHeader * hdr, const HttpHdrCc * cc);
extern void httpHeaderPutContRange(HttpHeader * hdr, const HttpHdrContRange * cr);
extern void httpHeaderPutRange(HttpHeader * hdr, const HttpHdrRange * range);
extern void httpHeaderPutExt(HttpHeader * hdr, const char *name, const char *value);
extern int httpHeaderGetInt(const HttpHeader * hdr, http_hdr_type id);
extern time_t httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id);
extern TimeOrTag httpHeaderGetTimeOrTag(const HttpHeader * hdr, http_hdr_type id);
extern HttpHdrCc *httpHeaderGetCc(const HttpHeader * hdr);
extern ETag httpHeaderGetETag(const HttpHeader * hdr, http_hdr_type id);
extern HttpHdrRange *httpHeaderGetRange(const HttpHeader * hdr);
extern HttpHdrContRange *httpHeaderGetContRange(const HttpHeader * hdr);
extern const char *httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id);
extern const char *httpHeaderGetLastStr(const HttpHeader * hdr, http_hdr_type id);
extern const char *httpHeaderGetAuth(const HttpHeader * hdr, http_hdr_type id, const char *auth_scheme);
extern String httpHeaderGetList(const HttpHeader * hdr, http_hdr_type id);
extern String httpHeaderGetStrOrList(const HttpHeader * hdr, http_hdr_type id);
extern String httpHeaderGetByName(const HttpHeader * hdr, const char *name);
extern int httpHeaderDelByName(HttpHeader * hdr, const char *name);
extern int httpHeaderDelById(HttpHeader * hdr, http_hdr_type id);
extern void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos);
/* avoid using these low level routines */
extern HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos);
extern HttpHeaderEntry *httpHeaderFindEntry(const HttpHeader * hdr, http_hdr_type id);
extern void httpHeaderAddEntry(HttpHeader * hdr, HttpHeaderEntry * e);
extern HttpHeaderEntry *httpHeaderEntryClone(const HttpHeaderEntry * e);
extern void httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p);
/* store report about current header usage and other stats */
extern void httpHeaderStoreReport(StoreEntry * e);
extern void httpHdrMangleList(HttpHeader *, request_t *);

/* Http Msg (currently in HttpReply.c @?@ ) */
extern int httpMsgIsPersistent(http_version_t http_ver, const HttpHeader * hdr);
extern int httpMsgIsolateHeaders(const char **parse_start, const char **blk_start, const char **blk_end);

/* Http Reply */
extern void httpReplyInitModule(void);
/* create/destroy */
extern HttpReply *httpReplyCreate(void);
extern void httpReplyDestroy(HttpReply * rep);
/* reset: clean, then init */
extern void httpReplyReset(HttpReply * rep);
/* absorb: copy the contents of a new reply to the old one, destroy new one */
extern void httpReplyAbsorb(HttpReply * rep, HttpReply * new_rep);
/* parse returns -1,0,+1 on error,need-more-data,success */
extern int httpReplyParse(HttpReply * rep, const char *buf, ssize_t);
extern void httpReplyPackInto(const HttpReply * rep, Packer * p);
/* ez-routines */
/* mem-pack: returns a ready to use mem buffer with a packed reply */
extern MemBuf httpReplyPack(const HttpReply * rep);
/* swap: create swap-based packer, pack, destroy packer */
extern void httpReplySwapOut(const HttpReply * rep, StoreEntry * e);
/* set commonly used info with one call */
extern void httpReplySetHeaders(HttpReply * rep, http_version_t ver, http_status status,
    const char *reason, const char *ctype, int clen, time_t lmt, time_t expires);
/* do everything in one call: init, set, pack, clean, return MemBuf */
extern MemBuf httpPackedReply(http_version_t ver, http_status status, const char *ctype,
    int clen, time_t lmt, time_t expires);
/* construct 304 reply and pack it into MemBuf, return MemBuf */
extern MemBuf httpPacked304Reply(const HttpReply * rep);
/* update when 304 reply is received for a cached object */
extern void httpReplyUpdateOnNotModified(HttpReply * rep, HttpReply * freshRep);
/* header manipulation */
extern int httpReplyContentLen(const HttpReply * rep);
extern const char *httpReplyContentType(const HttpReply * rep);
extern time_t httpReplyExpires(const HttpReply * rep);
extern int httpReplyHasCc(const HttpReply * rep, http_hdr_cc_type type);
extern void httpRedirectReply(HttpReply *, http_status, const char *);
extern int httpReplyBodySize(method_t, HttpReply *);
extern void httpReplyBodyBuildSize(request_t *, HttpReply *, dlink_list *);

/* Http Request */
extern request_t *requestCreate(method_t, protocol_t, const char *urlpath);
extern void requestDestroy(request_t *);
extern request_t *requestLink(request_t *);
extern void requestUnlink(request_t *);
extern int httpRequestParseHeader(request_t * req, const char *parse_start);
extern void httpRequestSwapOut(const request_t * req, StoreEntry * e);
extern void httpRequestPack(const request_t * req, Packer * p);
extern int httpRequestPrefixLen(const request_t * req);
extern int httpRequestHdrAllowed(const HttpHeaderEntry * e, String * strConnection);
extern int httpRequestHdrAllowedByName(http_hdr_type id);

extern void icmpOpen(void);
extern void icmpClose(void);
extern void icmpPing(struct in_addr to);
extern void icmpSourcePing(struct in_addr to, const icp_common_t *, const char *url);
extern void icmpDomainPing(struct in_addr to, const char *domain);

extern void *icpCreateMessage(icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad);
extern int icpUdpSend(int, const struct sockaddr_in *, icp_common_t *, log_type, int);
extern PF icpHandleUdp;
extern PF icpUdpSendQueue;
extern PF httpAccept;

#ifdef SQUID_SNMP
extern PF snmpHandleUdp;
extern void snmpInit(void);
extern void snmpConnectionOpen(void);
extern void snmpConnectionShutdown(void);
extern void snmpConnectionClose(void);
extern void snmpDebugOid(int lvl, oid * Name, snint Len);
extern void addr2oid(struct in_addr addr, oid * Dest);
extern struct in_addr *oid2addr(oid * id);
extern struct in_addr *client_entry(struct in_addr *current);
extern variable_list *snmp_basicFn(variable_list *, snint *);
extern variable_list *snmp_confFn(variable_list *, snint *);
extern variable_list *snmp_sysFn(variable_list *, snint *);
extern variable_list *snmp_prfSysFn(variable_list *, snint *);
extern variable_list *snmp_prfProtoFn(variable_list *, snint *);
extern variable_list *snmp_prfPeerFn(variable_list *, snint *);
extern variable_list *snmp_netIpFn(variable_list *, snint *);
extern variable_list *snmp_netFqdnFn(variable_list *, snint *);
#if USE_DNSSERVERS
extern variable_list *snmp_netDnsFn(variable_list *, snint *);
#else
extern variable_list *snmp_netIdnsFn(variable_list *, snint *);
#endif
extern variable_list *snmp_meshPtblFn(variable_list *, snint *);
extern variable_list *snmp_meshCtblFn(variable_list *, snint *);
#endif /* SQUID_SNMP */

#if USE_WCCP
extern void wccpInit(void);
extern void wccpConnectionOpen(void);
extern void wccpConnectionShutdown(void);
extern void wccpConnectionClose(void);
#endif /* USE_WCCP */

extern void icpHandleIcpV3(int, struct sockaddr_in, char *, int);
extern int icpCheckUdpHit(StoreEntry *, request_t * request);
extern void icpConnectionsOpen(void);
extern void icpConnectionShutdown(void);
extern void icpConnectionClose(void);
extern int icpSetCacheKey(const cache_key * key);
extern const cache_key *icpGetCacheKey(const char *url, int reqnum);

extern void ipcache_nbgethostbyname(const char *name,
    IPH * handler,
    void *handlerData);
extern EVH ipcache_purgelru;
extern const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
extern void ipcacheInvalidate(const char *);
extern void ipcacheReleaseInvalid(const char *);
extern void ipcache_init(void);
extern void stat_ipcache_get(StoreEntry *);
extern int ipcacheQueueDrain(void);
extern void ipcacheCycleAddr(const char *name, ipcache_addrs *);
extern void ipcacheMarkBadAddr(const char *name, struct in_addr);
extern void ipcacheMarkGoodAddr(const char *name, struct in_addr);
extern void ipcacheFreeMemory(void);
extern ipcache_addrs *ipcacheCheckNumeric(const char *name);
extern void ipcache_restart(void);
extern int ipcacheAddEntryFromHosts(const char *name, const char *ipaddr);

/* MemBuf */
/* init with specific sizes */
extern void memBufInit(MemBuf * mb, mb_size_t szInit, mb_size_t szMax);
/* init with defaults */
extern void memBufDefInit(MemBuf * mb);
/* cleans mb; last function to call if you do not give .buf away */
extern void memBufClean(MemBuf * mb);
/* resets mb preserving (or initializing if needed) memory buffer */
extern void memBufReset(MemBuf * mb);
/* unfirtunate hack to test if the buffer has been Init()ialized */
extern int memBufIsNull(MemBuf * mb);
/* calls memcpy, appends exactly size bytes, extends buffer if needed */
extern void memBufAppend(MemBuf * mb, const char *buf, mb_size_t size);
/* calls snprintf, extends buffer if needed */
#if STDC_HEADERS
extern void
memBufPrintf(MemBuf * mb, const char *fmt,...) PRINTF_FORMAT_ARG2;
#else
extern void memBufPrintf();
#endif
/* vprintf for other printf()'s to use */
extern void memBufVPrintf(MemBuf * mb, const char *fmt, va_list ap);
/* returns free() function to be used, _freezes_ the object! */
extern FREE *memBufFreeFunc(MemBuf * mb);
/* puts report on MemBuf _module_ usage into mb */
extern void memBufReport(MemBuf * mb);

extern char *mime_get_header(const char *mime, const char *header);
extern char *mime_get_header_field(const char *mime, const char *name, const char *prefix);
extern size_t headersEnd(const char *, size_t);
extern const char *mime_get_auth(const char *hdr, const char *auth_scheme, const char **auth_field);

extern void mimeInit(char *filename);
extern void mimeFreeMemory(void);
extern char *mimeGetContentEncoding(const char *fn);
extern char *mimeGetContentType(const char *fn);
extern char *mimeGetIcon(const char *fn);
extern const char *mimeGetIconURL(const char *fn);
extern char mimeGetTransferMode(const char *fn);
extern int mimeGetDownloadOption(const char *fn);
extern int mimeGetViewOption(const char *fn);

extern int mcastSetTtl(int, int);
extern IPH mcastJoinGroups;

/* Labels for hierachical log file */
/* put them all here for easier reference when writing a logfile analyzer */


extern peer *getFirstPeer(void);
extern peer *getFirstUpParent(request_t *);
extern peer *getNextPeer(peer *);
extern peer *getSingleParent(request_t *);
extern int neighborsCount(request_t *);
extern int neighborsUdpPing(request_t *,
    StoreEntry *,
    IRCB * callback,
    void *data,
    int *exprep,
    int *timeout);
extern void neighborAddAcl(const char *, const char *);
extern void neighborsUdpAck(const cache_key *, icp_common_t *, const struct sockaddr_in *);
extern void neighborAdd(const char *, const char *, int, int, int, int, int);
extern void neighbors_open(int);
extern peer *peerFindByName(const char *);
extern peer *peerFindByNameAndPort(const char *, unsigned short);
extern peer *getDefaultParent(request_t * request);
extern peer *getRoundRobinParent(request_t * request);
EVH peerClearRR;
extern peer *getAnyParent(request_t * request);
extern lookup_t peerDigestLookup(peer * p, request_t * request);
extern peer *neighborsDigestSelect(request_t * request);
extern void peerNoteDigestLookup(request_t * request, peer * p, lookup_t lookup);
extern void peerNoteDigestGone(peer * p);
extern int neighborUp(const peer * e);
extern CBDUNL peerDestroy;
extern const char *neighborTypeStr(const peer * e);
extern peer_t neighborType(const peer *, const request_t *);
extern void peerConnectFailed(peer *);
extern void peerConnectSucceded(peer *);
extern void dump_peer_options(StoreEntry *, peer *);
extern int peerHTTPOkay(const peer *, request_t *);
extern peer *whichPeer(const struct sockaddr_in *from);
#if USE_HTCP
extern void neighborsHtcpReply(const cache_key *, htcpReplyData *, const struct sockaddr_in *);
#endif

extern void netdbInit(void);
extern void netdbHandlePingReply(const struct sockaddr_in *from, int hops, int rtt);
extern void netdbPingSite(const char *hostname);
extern void netdbDump(StoreEntry *);
extern int netdbHops(struct in_addr);
extern void netdbFreeMemory(void);
extern int netdbHostHops(const char *host);
extern int netdbHostRtt(const char *host);
extern int netdbHostPeerRtt(const char *host, peer * p);
extern void netdbUpdatePeer(request_t *, peer * e, int rtt, int hops);
extern void netdbDeleteAddrNetwork(struct in_addr addr);
extern void netdbBinaryExchange(StoreEntry *);
extern EVH netdbExchangeStart;
extern void netdbExchangeUpdatePeer(struct in_addr, peer *, double, double);
extern peer *netdbClosestParent(request_t *);
extern void netdbHostData(const char *host, int *samp, int *rtt, int *hops);

extern void cachemgrStart(int fd, request_t * request, StoreEntry * entry);
extern void cachemgrRegister(const char *, const char *, OBJH *, int, int);
extern void cachemgrInit(void);

extern void peerSelect(request_t *, StoreEntry *, PSC *, void *data);
extern void peerSelectInit(void);

/* peer_digest.c */
extern PeerDigest *peerDigestCreate(peer * p);
extern void peerDigestNeeded(PeerDigest * pd);
extern void peerDigestNotePeerGone(PeerDigest * pd);
extern void peerDigestStatsReport(const PeerDigest * pd, StoreEntry * e);

/* forward.c */
extern void fwdStart(int, StoreEntry *, request_t *);
extern DEFER fwdCheckDeferRead;
extern void fwdFail(FwdState *, ErrorState *);
extern void fwdUnregister(int fd, FwdState *);
extern void fwdComplete(FwdState * fwdState);
extern void fwdInit(void);
extern int fwdReforwardableStatus(http_status s);
extern void fwdServersFree(FwdServer ** FS);
#if WIP_FWD_LOG
extern void fwdUninit(void);
extern void fwdLogRotate(void);
extern void fwdStatus(FwdState *, http_status);
#endif
struct in_addr getOutgoingAddr(request_t * request);
unsigned long getOutgoingTOS(request_t * request);

extern void urnStart(request_t *, StoreEntry *);

extern void redirectStart(clientHttpRequest *, RH *, void *);
extern void redirectInit(void);
extern void redirectShutdown(void);

/* auth_modules.c */
extern void authSchemeSetup(void);

/* authenticate.c */
extern void authenticateAuthUserMerge(auth_user_t *, auth_user_t *);
extern auth_user_t *authenticateAuthUserNew(const char *);
extern int authenticateAuthSchemeId(const char *typestr);
extern void authenticateStart(auth_user_request_t *, RH *, void *);
extern void authenticateSchemeInit(void);
extern void authenticateInit(authConfig *);
extern void authenticateShutdown(void);
extern void authenticateFixHeader(HttpReply *, auth_user_request_t *, request_t *, int, int);
extern void authenticateAddTrailer(HttpReply *, auth_user_request_t *, request_t *, int);
extern auth_acl_t authenticateAuthenticate(auth_user_request_t **, http_hdr_type, request_t *, ConnStateData *, struct in_addr);
extern void authenticateAuthUserUnlock(auth_user_t * auth_user);
extern void authenticateAuthUserLock(auth_user_t * auth_user);
extern void authenticateAuthUserRequestUnlock(auth_user_request_t *);
extern void authenticateAuthUserRequestLock(auth_user_request_t *);
extern char *authenticateAuthUserRequestMessage(auth_user_request_t *);
extern int authenticateAuthUserInuse(auth_user_t * auth_user);
extern void authenticateAuthUserRequestSetIp(auth_user_request_t *, struct in_addr);
extern void authenticateAuthUserRequestRemoveIp(auth_user_request_t *, struct in_addr);
extern void authenticateAuthUserRequestClearIp(auth_user_request_t *);
extern size_t authenticateAuthUserRequestIPCount(auth_user_request_t *);
extern int authenticateDirection(auth_user_request_t *);
extern FREE authenticateFreeProxyAuthUser;
extern void authenticateFreeProxyAuthUserACLResults(void *data);
extern void authenticateProxyUserCacheCleanup(void *);
extern void authenticateInitUserCache(void);
extern int authenticateActiveSchemeCount(void);
extern int authenticateSchemeCount(void);
extern void authenticateUserNameCacheAdd(auth_user_t * auth_user);
extern int authenticateCheckAuthUserIP(struct in_addr request_src_addr, auth_user_request_t * auth_user);
extern int authenticateUserAuthenticated(auth_user_request_t *);
extern void authenticateUserCacheRestart(void);
extern char *authenticateUserUsername(auth_user_t *);
extern char *authenticateUserRequestUsername(auth_user_request_t *);
extern int authenticateValidateUser(auth_user_request_t *);
extern void authenticateOnCloseConnection(ConnStateData * conn);
extern void authSchemeAdd(const char *type, AUTHSSETUP * setup);

extern void refreshAddToList(const char *, int, time_t, int, time_t);
extern int refreshIsCachable(const StoreEntry *);
extern int refreshCheckHTTP(const StoreEntry *, request_t *);
extern int refreshCheckICP(const StoreEntry *, request_t *);
extern int refreshCheckHTCP(const StoreEntry *, request_t *);
extern int refreshCheckDigest(const StoreEntry *, time_t delta);
extern time_t getMaxAge(const char *url);
extern void refreshInit(void);

extern void serverConnectionsClose(void);
extern void shut_down(int);


extern void start_announce(void *unused);
extern void sslStart(int fd, const char *, request_t *, size_t *, int *);
extern void waisStart(FwdState *);

/* ident.c */
#if USE_IDENT
extern void identStart(struct sockaddr_in *me, struct sockaddr_in *my_peer,
    IDCB * callback, void *cbdata);
extern void identInit(void);
#endif

extern void statInit(void);
extern void statFreeMemory(void);
extern double median_svc_get(int, int);
extern void pconnHistCount(int, int);
extern int stat5minClientRequests(void);
extern double stat5minCPUUsage(void);
extern const char *storeEntryFlags(const StoreEntry *);
extern double statRequestHitRatio(int minutes);
extern double statRequestHitMemoryRatio(int minutes);
extern double statRequestHitDiskRatio(int minutes);
extern double statByteHitRatio(int minutes);
extern int storeEntryLocked(const StoreEntry *);


/* StatHist */
extern void statHistClean(StatHist * H);
extern void statHistCount(StatHist * H, double val);
extern void statHistCopy(StatHist * Dest, const StatHist * Orig);
extern void statHistSafeCopy(StatHist * Dest, const StatHist * Orig);
extern double statHistDeltaMedian(const StatHist * A, const StatHist * B);
extern void statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper * bd);
extern void statHistLogInit(StatHist * H, int capacity, double min, double max);
extern void statHistEnumInit(StatHist * H, int last_enum);
extern void statHistIntInit(StatHist * H, int n);
extern StatHistBinDumper statHistEnumDumper;
extern StatHistBinDumper statHistIntDumper;


/* mem */
extern void memInit(void);
extern void memClean(void);
extern void memInitModule(void);
extern void memCleanModule(void);
extern void memConfigure(void);
extern void *memAllocate(mem_type);
extern void *memAllocString(size_t net_size, size_t * gross_size);
extern void *memAllocBuf(size_t net_size, size_t * gross_size);
extern void *memReallocBuf(void *buf, size_t net_size, size_t * gross_size);
extern void memFree(void *, int type);
extern void memFree4K(void *);
extern void memFree8K(void *);
extern void memFreeString(size_t size, void *);
extern void memFreeBuf(size_t size, void *);
extern FREE *memFreeBufFunc(size_t size);
extern int memInUse(mem_type);
extern void memDataInit(mem_type, const char *, size_t, int);
extern void memCheckInit(void);

/* MemPool */
extern MemPool *memPoolCreate(const char *label, size_t obj_size);
extern void *memPoolAlloc(MemPool * pool);
extern void memPoolFree(MemPool * pool, void *obj);
extern void memPoolDestroy(MemPool ** pool);
extern MemPoolIterator *memPoolGetFirst(void);
extern MemPool *memPoolGetNext(MemPoolIterator ** iter);
extern void memPoolSetChunkSize(MemPool * pool, size_t chunksize);
extern void memPoolSetIdleLimit(size_t new_idle_limit);
extern int memPoolGetStats(MemPoolStats * stats, MemPool * pool);
extern int memPoolGetGlobalStats(MemPoolGlobalStats * stats);
extern void memPoolClean(time_t maxage);

/* Mem */
extern void memReport(StoreEntry * e);
extern void memConfigure(void);
extern void memPoolCleanIdlePools(void *unused);
extern int memPoolInUseCount(MemPool * pool);
extern int memPoolsTotalAllocated(void);

extern int stmemFreeDataUpto(mem_hdr *, int);
extern void stmemAppend(mem_hdr *, const char *, int);
extern ssize_t stmemCopy(const mem_hdr *, off_t, char *, size_t);
extern void stmemFree(mem_hdr *);
extern void stmemFreeData(mem_hdr *);

/* ----------------------------------------------------------------- */

/*
 * store.c
 */
extern StoreEntry *new_StoreEntry(int, const char *, const char *);
extern StoreEntry *storeGet(const cache_key *);
extern StoreEntry *storeGetPublic(const char *uri, const method_t method);
extern StoreEntry *storeGetPublicByRequest(request_t * request);
extern StoreEntry *storeGetPublicByRequestMethod(request_t * request, const method_t method);
extern StoreEntry *storeCreateEntry(const char *, const char *, request_flags, method_t);
extern void storeSetPublicKey(StoreEntry *);
extern void storeComplete(StoreEntry *);
extern void storeInit(void);
extern int storeClientWaiting(const StoreEntry *);
extern void storeAbort(StoreEntry *);
extern void storeAppend(StoreEntry *, const char *, int);
extern void storeLockObject(StoreEntry *);
extern void storeRelease(StoreEntry *);
extern int storeUnlockObject(StoreEntry *);
extern EVH storeMaintainSwapSpace;
extern void storeExpireNow(StoreEntry *);
extern void storeReleaseRequest(StoreEntry *);
extern void storeConfigure(void);
extern void storeNegativeCache(StoreEntry *);
extern void storeFreeMemory(void);
extern int expiresMoreThan(time_t, time_t);
extern int storeEntryValidToSend(StoreEntry *);
extern void storeTimestampsSet(StoreEntry *);
extern void storeRegisterAbort(StoreEntry * e, STABH * cb, void *);
extern void storeUnregisterAbort(StoreEntry * e);
extern void storeMemObjectDump(MemObject * mem);
extern void storeEntryDump(const StoreEntry * e, int debug_lvl);
extern const char *storeUrl(const StoreEntry *);
extern void storeCreateMemObject(StoreEntry *, const char *, const char *);
extern void storeCopyNotModifiedReplyHeaders(MemObject * O, MemObject * N);
extern void storeBuffer(StoreEntry *);
extern void storeBufferFlush(StoreEntry *);
extern void storeHashInsert(StoreEntry * e, const cache_key *);
extern void storeSetMemStatus(StoreEntry * e, int);
#if STDC_HEADERS
extern void
storeAppendPrintf(StoreEntry *, const char *,...) PRINTF_FORMAT_ARG2;
#else
extern void storeAppendPrintf();
#endif
extern void storeAppendVPrintf(StoreEntry *, const char *, va_list ap);
extern int storeCheckCachable(StoreEntry * e);
extern void storeSetPrivateKey(StoreEntry *);
extern int objectLen(const StoreEntry * e);
extern int contentLen(const StoreEntry * e);
extern HttpReply *storeEntryReply(StoreEntry *);
extern int storeTooManyDiskFilesOpen(void);
extern void storeEntryReset(StoreEntry *);
extern void storeHeapPositionUpdate(StoreEntry *, SwapDir *);
extern void storeSwapFileNumberSet(StoreEntry * e, sfileno filn);
extern void storeFsInit(void);
extern void storeFsDone(void);
extern void storeFsAdd(const char *, STSETUP *);
extern void storeReplAdd(const char *, REMOVALPOLICYCREATE *);

/* store_modules.c */
extern void storeFsSetup(void);

/* repl_modules.c */
extern void storeReplSetup(void);

/* store_io.c */
extern storeIOState *storeCreate(StoreEntry *, STFNCB *, STIOCB *, void *);
extern storeIOState *storeOpen(StoreEntry *, STFNCB *, STIOCB *, void *);
extern void storeClose(storeIOState *);
extern void storeRead(storeIOState *, char *, size_t, off_t, STRCB *, void *);
extern void storeWrite(storeIOState *, char *, size_t, off_t, FREE *);
extern void storeUnlink(StoreEntry *);
extern off_t storeOffset(storeIOState *);

/*
 * store_log.c
 */
extern void storeLog(int tag, const StoreEntry * e);
extern void storeLogRotate(void);
extern void storeLogClose(void);
extern void storeLogOpen(void);


/*
 * store_key_*.c
 */
extern cache_key *storeKeyDup(const cache_key *);
extern cache_key *storeKeyCopy(cache_key *, const cache_key *);
extern void storeKeyFree(const cache_key *);
extern const cache_key *storeKeyScan(const char *);
extern const char *storeKeyText(const cache_key *);
extern const cache_key *storeKeyPublic(const char *, const method_t);
extern const cache_key *storeKeyPublicByRequest(request_t *);
extern const cache_key *storeKeyPublicByRequestMethod(request_t *, const method_t);
extern const cache_key *storeKeyPrivate(const char *, method_t, int);
extern int storeKeyHashBuckets(int);
extern int storeKeyNull(const cache_key *);
extern void storeKeyInit(void);
extern HASHHASH storeKeyHashHash;
extern HASHCMP storeKeyHashCmp;

/*
 * store_digest.c
 */
extern void storeDigestInit(void);
extern void storeDigestNoteStoreReady(void);
extern void storeDigestScheduleRebuild(void);
extern void storeDigestDel(const StoreEntry * entry);
extern void storeDigestReport(StoreEntry *);

/*
 * store_dir.c
 */
extern OBJH storeDirStats;
extern char *storeDirSwapLogFile(int, const char *);
extern char *storeSwapDir(int);
extern char *storeSwapFullPath(int, char *);
extern char *storeSwapSubSubDir(int, char *);
extern const char *storeSwapPath(int);
extern int storeDirWriteCleanLogs(int reopen);
extern STDIRSELECT *storeDirSelectSwapDir;
extern int storeVerifySwapDirs(void);
extern void storeCreateSwapDirectories(void);
extern void storeDirCloseSwapLogs(void);
extern void storeDirCloseTmpSwapLog(int dirn);
extern void storeDirConfigure(void);
extern void storeDirDiskFull(sdirno);
extern void storeDirInit(void);
extern void storeDirOpenSwapLogs(void);
extern void storeDirSwapLog(const StoreEntry *, int op);
extern void storeDirUpdateSwapSize(SwapDir *, size_t size, int sign);
extern void storeDirSync(void);
extern void storeDirCallback(void);
extern void storeDirLRUDelete(StoreEntry *);
extern void storeDirLRUAdd(StoreEntry *);
extern int storeDirGetBlkSize(const char *path, int *blksize);
extern int storeDirGetUFSStats(const char *, int *, int *, int *, int *);

/*
 * store_swapmeta.c
 */
extern char *storeSwapMetaPack(tlv * tlv_list, int *length);
extern tlv *storeSwapMetaBuild(StoreEntry * e);
extern tlv *storeSwapMetaUnpack(const char *buf, int *hdrlen);
extern void storeSwapTLVFree(tlv * n);

/*
 * store_rebuild.c
 */
extern void storeRebuildStart(void);
extern void storeRebuildComplete(struct _store_rebuild_data *);
extern void storeRebuildProgress(int sd_index, int total, int sofar);

/*
 * store_swapin.c
 */
extern void storeSwapInStart(store_client *);

/*
 * store_swapout.c
 */
extern void storeSwapOut(StoreEntry * e);
extern void storeSwapOutFileClose(StoreEntry * e);
extern int storeSwapOutAble(const StoreEntry * e);

/*
 * store_client.c
 */
extern store_client *storeClientListAdd(StoreEntry * e, void *data);
extern void storeClientCopyOld(store_client *, StoreEntry *, off_t, off_t, size_t, char *, STCB *, void *);
extern void storeClientCopy(store_client *, StoreEntry *, off_t, size_t, char *, STCB *, void *);
extern int storeClientCopyPending(store_client *, StoreEntry * e, void *data);
extern int storeUnregister(store_client * sc, StoreEntry * e, void *data);
extern off_t storeLowestMemReaderOffset(const StoreEntry * entry);
extern void InvokeHandlers(StoreEntry * e);
extern int storePendingNClients(const StoreEntry * e);


extern const char *getMyHostname(void);
extern const char *uniqueHostname(void);
extern void safeunlink(const char *path, int quiet);
extern void death(int sig);
extern void fatal(const char *message);
#if STDC_HEADERS
extern void
fatalf(const char *fmt,...) PRINTF_FORMAT_ARG1;
#else
extern void fatalf();
#endif
extern void fatal_dump(const char *message);
extern void sigusr2_handle(int sig);
extern void sig_child(int sig);
extern void leave_suid(void);
extern void enter_suid(void);
extern void no_suid(void);
extern void writePidFile(void);
extern void setSocketShutdownLifetimes(int);
extern void setMaxFD(void);
extern time_t getCurrentTime(void);
extern int percent(int, int);
extern double dpercent(double, double);
extern void squid_signal(int sig, SIGHDLR *, int flags);
extern pid_t readPidFile(void);
extern struct in_addr inaddrFromHostent(const struct hostent *hp);
extern int intAverage(int, int, int, int);
extern double doubleAverage(double, double, int, int);
extern void debug_trap(const char *);
extern void logsFlush(void);
extern const char *checkNullString(const char *p);
extern void squid_getrusage(struct rusage *r);
extern double rusage_cputime(struct rusage *r);
extern int rusage_maxrss(struct rusage *r);
extern int rusage_pagefaults(struct rusage *r);
extern void releaseServerSockets(void);
extern void PrintRusage(void);
extern void dumpMallocStats(void);

#if USE_UNLINKD
extern void unlinkdInit(void);
extern void unlinkdClose(void);
extern void unlinkdUnlink(const char *);
#endif

extern char *url_convert_hex(char *org_url, int allocate);
extern char *url_escape(const char *url);
extern protocol_t urlParseProtocol(const char *);
extern method_t urlParseMethod(const char *);
extern void urlInitialize(void);
extern request_t *urlParse(method_t, char *);
extern const char *urlCanonical(request_t *);
extern char *urlRInternal(const char *host, u_short port, const char *dir, const char *name);
extern char *urlInternal(const char *dir, const char *name);
extern int matchDomainName(const char *host, const char *domain);
extern int urlCheckRequest(const request_t *);
extern int urlDefaultPort(protocol_t p);
extern char *urlCanonicalClean(const request_t *);
extern char *urlHostname(const char *url);
extern void urlExtMethodConfigure(void);

extern void useragentOpenLog(void);
extern void useragentRotateLog(void);
extern void logUserAgent(const char *, const char *);
extern void useragentLogClose(void);
extern void refererOpenLog(void);
extern void refererRotateLog(void);
extern void logReferer(const char *, const char *, const char *);
extern peer_t parseNeighborType(const char *s);

extern void errorInitialize(void);
extern void errorClean(void);
extern HttpReply *errorBuildReply(ErrorState * err);
extern void errorSend(int fd, ErrorState *);
extern void errorAppendEntry(StoreEntry *, ErrorState *);
extern void errorStateFree(ErrorState * err);
extern int errorReservePageId(const char *page_name);
extern ErrorState *errorCon(err_type type, http_status);

extern void pconnPush(int, const char *host, u_short port);
extern int pconnPop(const char *host, u_short port);
extern void pconnInit(void);

extern int asnMatchIp(void *, struct in_addr);
extern void asnInit(void);
extern void asnFreeMemory(void);

/* tools.c */
extern void dlinkAdd(void *data, dlink_node *, dlink_list *);
extern void dlinkAddTail(void *data, dlink_node *, dlink_list *);
extern void dlinkDelete(dlink_node * m, dlink_list * list);
extern void dlinkNodeDelete(dlink_node * m);
extern dlink_node *dlinkNodeNew(void);

extern void kb_incr(kb_t *, size_t);
extern int stringHasWhitespace(const char *);
extern int stringHasCntl(const char *);
extern void linklistPush(link_list **, void *);
extern void *linklistShift(link_list **);
extern int xrename(const char *from, const char *to);
extern int isPowTen(int);
extern void parseEtcHosts(void);
extern int getMyPort(void);

#if USE_HTCP
extern void htcpInit(void);
extern void htcpQuery(StoreEntry * e, request_t * req, peer * p);
extern void htcpSocketShutdown(void);
extern void htcpSocketClose(void);
#endif

/* String */
#define strLen(s)     ((/* const */ int)(s).len)
#define strBuf(s)     ((const char*)(s).buf)
#define strChr(s,ch)  ((const char*)strchr(strBuf(s), (ch)))
#define strRChr(s,ch) ((const char*)strrchr(strBuf(s), (ch)))
#define strStr(s,str) ((const char*)strstr(strBuf(s), (str)))
#define strCmp(s,str)     strcmp(strBuf(s), (str))
#define strNCmp(s,str,n)     strncmp(strBuf(s), (str), (n))
#define strCaseCmp(s,str) strcasecmp(strBuf(s), (str))
#define strNCaseCmp(s,str,n) strncasecmp(strBuf(s), (str), (n))
#define strSet(s,ptr,ch) (s).buf[ptr-(s).buf] = (ch)
#define strCut(s,pos) (((s).len = pos) , ((s).buf[pos] = '\0'))
#define strCutPtr(s,ptr) (((s).len = (ptr)-(s).buf) , ((s).buf[(s).len] = '\0'))
#define strCat(s,str)  stringAppend(&(s), (str), strlen(str))
extern void stringInit(String * s, const char *str);
extern void stringLimitInit(String * s, const char *str, int len);
extern String stringDup(const String * s);
extern void stringClean(String * s);
extern void stringReset(String * s, const char *str);
extern void stringAppend(String * s, const char *buf, int len);
/* extern void stringAppendf(String *s, const char *fmt, ...) PRINTF_FORMAT_ARG2; */

/*
 * ipc.c
 */
extern int ipcCreate(int type,
    const char *prog,
    const char *const args[],
    const char *name,
    int *rfd,
    int *wfd);

/* CacheDigest */
extern CacheDigest *cacheDigestCreate(int capacity, int bpe);
extern void cacheDigestDestroy(CacheDigest * cd);
extern CacheDigest *cacheDigestClone(const CacheDigest * cd);
extern void cacheDigestClear(CacheDigest * cd);
extern void cacheDigestChangeCap(CacheDigest * cd, int new_cap);
extern int cacheDigestTest(const CacheDigest * cd, const cache_key * key);
extern void cacheDigestAdd(CacheDigest * cd, const cache_key * key);
extern void cacheDigestDel(CacheDigest * cd, const cache_key * key);
extern size_t cacheDigestCalcMaskSize(int cap, int bpe);
extern int cacheDigestBitUtil(const CacheDigest * cd);
extern void cacheDigestGuessStatsUpdate(cd_guess_stats * stats, int real_hit, int guess_hit);
extern void cacheDigestGuessStatsReport(const cd_guess_stats * stats, StoreEntry * sentry, const char *label);
extern void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

extern void internalStart(request_t *, StoreEntry *);
extern int internalCheck(const char *urlpath);
extern int internalStaticCheck(const char *urlpath);
extern char *internalLocalUri(const char *dir, const char *name);
extern char *internalRemoteUri(const char *, u_short, const char *, const char *);
extern const char *internalHostname(void);
extern int internalHostnameIs(const char *);

#if USE_CARP
extern void carpInit(void);
extern peer *carpSelectParent(request_t *);
#endif

#if DELAY_POOLS
extern void delayPoolsInit(void);
extern void delayInitDelayData(unsigned short pools);
extern void delayFreeDelayData(unsigned short pools);
extern void delayCreateDelayPool(unsigned short pool, u_char class);
extern void delayInitDelayPool(unsigned short pool, u_char class, delaySpecSet * rates);
extern void delayFreeDelayPool(unsigned short pool);
extern void delayPoolsReconfigure(void);
extern void delaySetNoDelay(int fd);
extern void delayClearNoDelay(int fd);
extern int delayIsNoDelay(int fd);
extern delay_id delayClient(request_t *);
extern EVH delayPoolsUpdate;
extern int delayBytesWanted(delay_id d, int min, int max);
extern void delayBytesIn(delay_id, int qty);
extern int delayMostBytesWanted(const MemObject * mem, int max);
extern delay_id delayMostBytesAllowed(const MemObject * mem);
extern void delaySetStoreClient(store_client * sc, delay_id delay_id);
extern void delayRegisterDelayIdPtr(delay_id * loc);
extern void delayUnregisterDelayIdPtr(delay_id * loc);
#endif

/* helper.c */
extern void helperOpenServers(helper * hlp);
extern void helperStatefulOpenServers(statefulhelper * hlp);
extern void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
extern void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver);
extern void helperStats(StoreEntry * sentry, helper * hlp);
extern void helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp);
extern void helperShutdown(helper * hlp);
extern void helperStatefulShutdown(statefulhelper * hlp);
extern helper *helperCreate(const char *);
extern statefulhelper *helperStatefulCreate(const char *);
extern void helperFree(helper *);
extern void helperStatefulFree(statefulhelper *);
extern void helperStatefulReset(helper_stateful_server * srv);
extern void helperStatefulReleaseServer(helper_stateful_server * srv);
extern void *helperStatefulServerGetData(helper_stateful_server * srv);
extern helper_stateful_server *helperStatefulDefer(statefulhelper *);



#if USE_LEAKFINDER
extern void leakInit(void);
extern void *leakAddFL(void *, const char *, int);
extern void *leakTouchFL(void *, const char *, int);
extern void *leakFreeFL(void *, const char *, int);
#endif

/* logfile.c */
extern Logfile *logfileOpen(const char *path, size_t bufsz, int);
extern void logfileClose(Logfile * lf);
extern void logfileRotate(Logfile * lf);
extern void logfileWrite(Logfile * lf, void *buf, size_t len);
extern void logfileFlush(Logfile * lf);
#if STDC_HEADERS
extern void
logfilePrintf(Logfile * lf, const char *fmt,...) PRINTF_FORMAT_ARG2;
#else
extern void logfilePrintf(va_alist);
#endif

/*
 * Removal Policies
 */
extern RemovalPolicy *createRemovalPolicy(RemovalPolicySettings * settings);

/*
 * prototypes for system functions missing from system includes
 */

#ifdef _SQUID_SOLARIS_
extern int getrusage(int, struct rusage *);
extern int getpagesize(void);
extern int gethostname(char *, int);
#endif

#if URL_CHECKSUM_DEBUG
extern unsigned int url_checksum(const char *url);
#endif

/*
 * hack to allow snmp access to the statistics counters
 */
extern StatCounters *snmpStatGet(int);

/* Vary support functions */
int varyEvaluateMatch(StoreEntry * entry, request_t * req);

/* CygWin & Windows NT Port */
/* win32.c */
#if defined(_SQUID_MSWIN_) || defined(_SQUID_CYGWIN_)
extern int WIN32_Subsystem_Init(void);
extern void WIN32_Exit(void);
#endif

#endif /* SQUID_PROTOS_H */
