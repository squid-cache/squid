

extern void accessLogLog(AccessLogEntry *);
extern void accessLogRotate(void);
extern void accessLogClose(void);
extern void accessLogInit(void);
extern void hierarchyNote(HierarchyLogEntry *, hier_code, icp_ping_data *, const char *);

extern aclCheck_t *aclChecklistCreate(const struct _acl_access *,
    request_t *,
    struct in_addr src,
    char *ua,
    char *id);
extern void aclNBCheck(aclCheck_t *, PF *, void *);
extern int aclCheckFast(const struct _acl_access *A, aclCheck_t *);
extern void aclChecklistFree(aclCheck_t *);
extern int aclMatchAcl(struct _acl *, aclCheck_t *);
extern void aclDestroyAccessList(struct _acl_access **list);
extern void aclDestroyAcls(acl **);
extern void aclParseAccessLine(struct _acl_access **);
extern void aclParseAclLine(acl **);
extern struct _acl *aclFindByName(const char *name);
extern char *aclGetDenyInfoUrl(struct _acl_deny_info_list **, const char *name);
extern void aclParseDenyInfoLine(struct _acl_deny_info_list **);
extern void aclDestroyDenyInfoList(struct _acl_deny_info_list **);
extern void aclDestroyRegexList(struct _relist *data);
extern int aclMatchRegex(relist * data, const char *word);
extern void aclParseRegexList(void *curlist);

#if USE_ASYNC_IO
extern int aio_cancel(aio_result_t *);
extern int aio_open(const char *, int, mode_t, aio_result_t *);
extern int aio_read(int, char *, int, off_t, int, aio_result_t *);
extern int aio_write(int, char *, int, off_t, int, aio_result_t *);
extern int aio_close(int, aio_result_t *);
extern int aio_stat(const char *, struct stat *, aio_result_t *);
extern int aio_unlink(const char *, aio_result_t *);
extern int aio_opendir(const char *, aio_result_t *);
extern aio_result_t *aio_poll_done(void);

extern void aioCancel(int, void *);
extern void aioOpen(const char *, int, mode_t, AIOCB *, void *, void *);
extern void aioClose(int);
extern void aioWrite(int, char *, int, AIOCB *, void *);
extern void aioRead(int, char *, int, AIOCB *, void *);
extern void aioStat(char *, struct stat *, AIOCB *, void *, void *);
extern void aioUnlink(const char *, AIOCB *, void *);
extern void aioCheckCallbacks(void);
#endif

extern int parseConfigFile(const char *file_name);
extern void intlistDestroy(intlist **);
extern void wordlistDestroy(wordlist **);
extern void configFreeMemory(void);

extern void cbdataInit(void);
#if CBDATA_DEBUG
extern void cbdataAddDbg(const void *p, mem_type, const char *, int);
#else
extern void cbdataAdd(const void *p, mem_type);
#endif
extern void cbdataFree(void *p);
extern void cbdataLock(const void *p);
extern void cbdataUnlock(const void *p);
extern int cbdataValid(const void *p);
extern void cbdataDump(StoreEntry *);

extern void clientdbInit(void);
extern void clientdbUpdate(struct in_addr, log_type, protocol_t);
extern int clientdbDeniedPercent(struct in_addr);
extern void clientdbDump(StoreEntry *);

extern void clientAccessCheck(void *);
extern void clientAccessCheckDone(int, void *);
extern int modifiedSince(StoreEntry *, request_t *);
extern char *clientConstructTraceEcho(clientHttpRequest *);
extern void clientPurgeRequest(clientHttpRequest *);
extern int checkNegativeHit(StoreEntry *);
extern void clientHttpConnectionsOpen(void);
extern void clientHttpConnectionsClose(void);
extern StoreEntry *clientCreateStoreEntry(clientHttpRequest *, method_t, int);

extern int commSetNonBlocking(int fd);
extern void commSetCloseOnExec(int fd);
extern int comm_accept(int fd, struct sockaddr_in *, struct sockaddr_in *);
extern void comm_close(int fd);
extern void commConnectStart(int fd, const char *, u_short, CNCB *, void *);
extern int comm_connect_addr(int sock, const struct sockaddr_in *);
extern int comm_init(void);
extern int comm_listen(int sock);
extern int comm_open(int, int, struct in_addr, u_short port, int, const char *note);
extern u_short comm_local_port(int fd);
#if HAVE_POLL
extern int comm_poll(time_t);
#else
extern int comm_select(time_t);
#endif
extern void commSetSelect(int, unsigned int, PF *, void *, time_t);
extern void comm_add_close_handler(int fd, PF *, void *);
extern void comm_remove_close_handler(int fd, PF *, void *);
extern int comm_udp_sendto(int fd, const struct sockaddr_in *, int size, const char *buf, int len);
extern void comm_write(int fd,
    char *buf,
    int size,
    CWCB * handler,
    void *handler_data,
    FREE *);
extern void commCallCloseHandlers(int fd);
extern int commSetTimeout(int fd, int, PF *, void *);
extern void commSetDefer(int fd, DEFER * func, void *);
extern int ignoreErrno(int);

extern void _db_init(const char *logfile, const char *options);
extern void _db_rotate_log(void);

#ifdef __STDC__
extern void _db_print(const char *,...);
#else
extern void _db_print();
#endif


extern int file_open(const char *path, int mode, FOCB *, void *callback_data, void *tag);
extern void file_close(int fd);
extern void file_write(int, off_t, void *, int len, DWCB *, void *, FREE *);
extern int file_read(int, char *, int, off_t, DRCB *, void *);
extern int disk_init(void);
extern int diskWriteIsComplete(int);

extern void dnsShutdownServers(void);
extern void dnsShutdownServer(dnsserver_t * dns);
extern void dnsOpenServers(void);
extern dnsserver_t *dnsGetFirstAvailable(void);
extern void dnsStats(StoreEntry *);
extern void dnsFreeMemory(void);

extern void eventAdd(const char *name, EVH * func, void *arg, time_t when);
extern void eventRun(void);
extern time_t eventNextTime(void);
extern void eventDelete(EVH * func, void *arg);

extern void fd_close(int fd);
extern void fd_open(int fd, unsigned int type, const char *);
extern void fd_note(int fd, const char *);
extern void fd_bytes(int fd, int len, unsigned int type);
extern void fdFreeMemory(void);
extern void fdDumpOpen(void);

extern void fdstat_init(void);
extern int fdstat_are_n_free_fd(int);

extern fileMap *file_map_create(int);
extern int file_map_allocate(fileMap *, int);
extern int file_map_bit_set(fileMap *, int);
extern int file_map_bit_test(fileMap *, int);
extern void file_map_bit_reset(fileMap *, int);
extern void filemapFreeMemory(fileMap *);


extern void fqdncache_nbgethostbyaddr(struct in_addr, FQDNH *, void *);
extern int fqdncacheUnregister(struct in_addr, void *);
extern const char *fqdncache_gethostbyaddr(struct in_addr, int flags);
extern void fqdncache_init(void);
extern void fqdnStats(StoreEntry *);
extern void fqdncacheReleaseInvalid(const char *);
extern const char *fqdnFromAddr(struct in_addr);
extern int fqdncacheQueueDrain(void);
extern void fqdncacheFreeMemory(void);
extern void fqdncache_restart(void);

extern void ftpStart(request_t * req, StoreEntry * entry);
extern char *ftpUrlWith2f(const request_t *);

extern void gopherStart(StoreEntry *);
extern int gopherCachable(const char *);


extern void whoisStart(request_t * req, StoreEntry *);

/* init */
extern hash_table *hash_create(HASHCMP *, int, HASHHASH *);
extern void hash_insert(hash_table *, const char *, void *);
extern int hash_delete(hash_table *, const char *);
extern int hash_delete_link(hash_table *, hash_link *);
extern void hash_join(hash_table *, hash_link *);
extern int hash_remove_link(hash_table *, hash_link *);

/* searching, accessing */
extern hash_link *hash_lookup(hash_table *, const void *);
extern hash_link *hash_first(hash_table *);
extern hash_link *hash_next(hash_table *);
extern hash_link *hash_get_bucket(hash_table *, unsigned int);
extern void hashFreeMemory(hash_table *);
extern HASHHASH hash_string;
extern HASHHASH hash_url;
extern HASHHASH hash4;

extern int httpCachable(method_t);
extern void httpStart(request_t *, StoreEntry *, peer *);
extern void httpParseReplyHeaders(const char *, struct _http_reply *);
extern void httpProcessReplyHeader(HttpStateData *, const char *, int);
extern void httpReplyHeaderStats(StoreEntry *);
extern size_t httpBuildRequestHeader(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    size_t * in_len,
    char *hdr_out,
    size_t out_sz,
    int cfd,
    int flags);
extern int httpAnonAllowed(const char *line);
extern int httpAnonDenied(const char *line);
extern char *httpReplyHeader(double ver,
    http_status status,
    char *ctype,
    int clen,
    time_t lmt,
    time_t expires);


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
extern void icpUdpSend(int fd,
    const struct sockaddr_in *,
    icp_common_t * msg,
    log_type,
    protocol_t);
extern PF icpHandleUdp;
extern PF httpAccept;
extern DEFER httpAcceptDefer;

#ifdef SQUID_SNMP
extern PF snmpHandleUdp;
extern void snmpInit(void);
extern void snmpConnectionOpen(void);
extern void snmpConnectionClose(void);
extern int create_view(char **);
extern int create_user(char **);
extern int create_community(char **);
extern void tokenize(char *, char **, int);
extern int snmpCompare(oid * name1, int len1, oid * name2, int len2);
#endif /* SQUID_SNMP */

extern void AppendUdp(icpUdpData *);
extern PF icpUdpReply;
extern void icpHandleIcpV3(int, struct sockaddr_in, char *, int);
extern int icpCheckUdpHit(StoreEntry *, request_t * request);
extern void icpConnectionsOpen(void);
extern void icpConnectionsClose(void);

extern void ipcache_nbgethostbyname(const char *name,
    IPH * handler,
    void *handlerData);
extern EVH ipcache_purgelru;
extern const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
extern void ipcacheInvalidate(const char *);
extern void ipcacheReleaseInvalid(const char *);
extern void ipcacheShutdownServers(void);
extern void ipcache_init(void);
extern void stat_ipcache_get(StoreEntry *);
extern int ipcacheQueueDrain(void);
extern void ipcacheCycleAddr(const char *name);
extern void ipcacheMarkBadAddr(const char *name, struct in_addr);
extern void ipcacheMarkGoodAddr(const char *name, struct in_addr);
extern void ipcacheFreeMemory(void);
extern ipcache_addrs *ipcacheCheckNumeric(const char *name);
extern void ipcache_restart(void);
extern int ipcacheUnregister(const char *name, void *data);

extern char *mime_get_header(const char *mime, const char *header);
extern char *mime_headers_end(const char *mime);
extern int mk_mime_hdr(char *result, const char *type, int size, time_t ttl, time_t lmt);
extern void mimeInit(char *filename);
extern char *mimeGetContentEncoding(const char *fn);
extern char *mimeGetContentType(const char *fn);
extern char *mimeGetIcon(const char *fn);
extern char mimeGetTransferMode(const char *fn);

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
    int *exprep);
extern void neighborAddAcl(const char *, const char *);
extern void neighborsUdpAck(const char *, icp_common_t *, const struct sockaddr_in *, StoreEntry *);
extern void neighborAdd(const char *, const char *, int, int, int, int, int);
extern void neighbors_open(int);
extern peer *peerFindByName(const char *);
extern peer *getDefaultParent(request_t * request);
extern peer *getRoundRobinParent(request_t * request);
extern int neighborUp(const peer * e);
extern void peerDestroy(peer * e);
extern char *neighborTypeStr(const peer * e);
extern void peerCheckConnectStart(peer *);

extern void netdbInit(void);

extern void netdbHandlePingReply(const struct sockaddr_in *from, int hops, int rtt);
extern void netdbPingSite(const char *hostname);
extern void netdbInit(void);
extern void netdbDump(StoreEntry *);
extern int netdbHops(struct in_addr);
extern void netdbFreeMemory(void);
extern int netdbHostHops(const char *host);
extern int netdbHostRtt(const char *host);
extern void netdbUpdatePeer(request_t *, peer * e, int rtt, int hops);

extern void objcachePasswdAdd(cachemgr_passwd **, char *, wordlist *);
extern void objcachePasswdDestroy(cachemgr_passwd ** a);
extern void objcacheStart(int fd, StoreEntry *);
extern void objcacheInit(void);

extern void peerSelect(request_t *, StoreEntry *, PSC *, PSC *, void *data);
extern peer *peerGetSomeParent(request_t *, hier_code *);
extern void peerSelectInit(void);

extern void protoDispatch(int, StoreEntry *, request_t *);

extern int protoUnregister(StoreEntry *, request_t *);
extern int protoAbortFetch(StoreEntry * entry);
extern DEFER protoCheckDeferRead;

extern void urnStart(request_t *, StoreEntry *);

extern void redirectStart(clientHttpRequest *, RH *, void *);
extern void redirectOpenServers(void);
extern void redirectShutdownServers(void);
extern void redirectStats(StoreEntry *);
extern int redirectUnregister(const char *url, void *);
extern void redirectFreeMemory(void);

extern void refreshAddToList(const char *, int, time_t, int, time_t);
extern int refreshCheck(const StoreEntry *, const request_t *, time_t delta);
extern time_t getMaxAge(const char *url);



extern void serverConnectionsClose(void);
extern void shut_down(int);


extern void start_announce(void *unused);
extern void sslStart(int fd, const char *, request_t *, size_t * sz);
extern void waisStart(request_t *, StoreEntry *);
extern void passStart(int, const char *, request_t *, size_t *);
extern void identStart(int, ConnStateData *, IDCB * callback);

extern void statInit(void);
extern void pconnHistCount(int, int);
extern int statMemoryAccounted(void);

extern void memInit(void);
extern void memFreeMemory(void);
extern void *memAllocate(mem_type, int);
extern void memFree(mem_type, void *);
extern void memFree4K(void *);
extern void memFree8K(void *);
extern void memFreeDISK(void *);
extern int memInUse(mem_type);
extern OBJH memStats;

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
extern StoreEntry *storeCreateEntry(const char *, const char *, int, method_t);
extern void storeSetPublicKey(StoreEntry *);
extern void storeComplete(StoreEntry *);
extern void storeInit(void);
extern int storeClientWaiting(const StoreEntry *);
extern void storeAbort(StoreEntry *, int);
extern void storeAppend(StoreEntry *, const char *, int);
extern void storeLockObject(StoreEntry *);
extern void storeSwapInStart(StoreEntry *, SIH *, void *data);
extern void storeRelease(StoreEntry *);
extern int storeUnlockObject(StoreEntry *);
extern int storeUnregister(StoreEntry *, void *);
extern void storeClientCopy(StoreEntry * e,
    off_t seen_offset,
    off_t copy_offset,
    size_t size,
    char *buf,
    STCB * callback,
    void *data);
extern int storePendingNClients(const StoreEntry *);
extern HASHCMP urlcmp;
extern EVH storeMaintainSwapSpace;
extern void storeExpireNow(StoreEntry *);
extern void storeReleaseRequest(StoreEntry *);
extern off_t storeLowestMemReaderOffset(const StoreEntry *);
extern void storeConfigure(void);
extern void storeNegativeCache(StoreEntry *);
extern void storeFreeMemory(void);
extern int expiresMoreThan(time_t, time_t);
extern int storeClientCopyPending(StoreEntry *, void *);
extern void InvokeHandlers(StoreEntry *);
extern int storeEntryValidToSend(StoreEntry *);
extern void storeTimestampsSet(StoreEntry *);
extern time_t storeExpiredReferenceAge(void);
extern void storeRegisterAbort(StoreEntry * e, STABH * cb, void *);
extern void storeUnregisterAbort(StoreEntry * e);
extern void storeMemObjectDump(MemObject * mem);
extern void storeEntryDump(StoreEntry * e, int debug_lvl);
extern const char *storeUrl(const StoreEntry *);
extern void storeCreateMemObject(StoreEntry *, const char *, const char *);
extern void storeCopyNotModifiedReplyHeaders(MemObject * O, MemObject * N);
extern void storeBuffer(StoreEntry *);
extern void storeBufferFlush(StoreEntry *);
extern void storeHashInsert(StoreEntry * e, const cache_key *);
extern void storeSetMemStatus(StoreEntry * e, int);
#if !MONOTONIC_STORE
extern int storeGetUnusedFileno(void);
extern void storePutUnusedFileno(StoreEntry * e);
#endif
#ifdef __STDC__
extern void storeAppendPrintf(StoreEntry *, const char *,...);
#else
extern void storeAppendPrintf();
#endif
extern int storeCheckCachable(StoreEntry * e);

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
extern const cache_key *storeKeyDup(const cache_key *);
extern void storeKeyFree(const cache_key *);
extern const cache_key *storeKeyScan(const char *);
extern const char *storeKeyText(const cache_key *);
extern const cache_key *storeKeyPublic(const char *, method_t);
extern const cache_key *storeKeyPrivate(const char *, method_t, int);
extern int storeKeyHashBuckets(int);
extern HASHHASH storeKeyHashHash;
extern HASHCMP storeKeyHashCmp;

/*
 * store_clean.c
 */
extern EVH storeDirClean;

/*
 * store_dir.c
 */
extern char *storeSwapFullPath(int, char *);
extern char *storeSwapSubSubDir(int, char *);
extern int storeVerifySwapDirs(void);
extern const char *storeSwapPath(int);
extern int storeDirMapBitTest(int fn);
extern void storeDirMapBitSet(int fn);
extern void storeDirMapBitReset(int fn);
extern int storeDirMapAllocate(void);
extern char *storeSwapDir(int);
extern FILE *storeDirOpenTmpSwapLog(int dirn, int *clean_flag);
extern void storeDirCloseTmpSwapLog(int dirn);
extern void storeDirOpenSwapLogs(void);
extern void storeDirCloseSwapLogs(void);
extern char *storeDirSwapLogFile(int, const char *);
extern void storeDirSwapLog(const StoreEntry *, int op);
extern int storeDirNumber(int fileno);
extern void storeDirUpdateSwapSize(int fn, size_t size, int sign);
extern int storeDirProperFileno(int dirn, int fn);
extern void storeCreateSwapDirectories(void);
extern int storeVerifyCacheDirs(void);
extern int storeDirWriteCleanLogs(int reopen);
extern int storeDirValidFileno(int fn);


/*
 * store_swapmeta.c
 */
char *storeSwapMetaPack(tlv * tlv_list, int *length);
tlv *storeSwapMetaBuild(StoreEntry * e);
tlv *storeSwapMetaUnpack(const char *buf, int *hdrlen);
void storeSwapTLVFree(tlv * n);

/*
 * store_rebuild.c
 */
extern void storeDoRebuildFromSwapFiles(void *data);
extern void storeConvertFile(const cache_key * key,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_short refcount,
    u_short flags,
    int clean);
extern StoreEntry *storeAddDiskRestore(const cache_key * key,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_num32 flags,
    int clean);
extern void storeCleanup(void *datanotused);
extern void storeValidate(StoreEntry *, STVLDCB, void *callback_data, void *tag);
extern void storeValidateComplete(void *data, int retcode, int errcode);
extern void storeRebuildStart(void);


/*
 * store_swapin.c
 */
extern void storeSwapInStart(StoreEntry * e, SIH * callback, void *callback_data);
extern void storeSwapInValidateComplete(void *data, int retcode, int errcode);
extern void storeSwapInFileOpened(void *data, int fd, int errcode);

/*
 * store_swapout.c
 */
extern void storeSwapOutStart(StoreEntry * e);
extern void storeSwapOutHandle(int fdnotused, int flag, size_t len, void *data);
extern void storeCheckSwapOut(StoreEntry * e);
extern void storeSwapOutFileClose(StoreEntry * e);
extern void storeSwapOutFileClose(StoreEntry * e);

/*
 * store_client.c
 */
extern store_client *storeClientListSearch(const MemObject * mem, void *data);
extern void storeClientListAdd(StoreEntry * e, void *data);
extern void storeClientCopy(StoreEntry *, off_t, off_t, size_t, char *, STCB *, void *);
extern int storeClientCopyPending(StoreEntry * e, void *data);
extern int storeUnregister(StoreEntry * e, void *data);
extern off_t storeLowestMemReaderOffset(const StoreEntry * entry);
extern void InvokeHandlers(StoreEntry * e);
extern int storePendingNClients(const StoreEntry * e);


extern const char *getMyHostname(void);
extern void safeunlink(const char *path, int quiet);
extern void death(int sig);
extern void fatal(const char *message);
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
extern void normal_shutdown(void);
extern int percent(int, int);
extern double dpercent(double, double);
extern void squid_signal(int sig, SIGHDLR *, int flags);
extern pid_t readPidFile(void);
extern struct in_addr inaddrFromHostent(const struct hostent *hp);
extern int intAverage(int, int, int, int);
extern double doubleAverage(double, double, int, int);
extern void debug_trap(const char *);
extern void logsFlush(void);
extern char *checkNullString(char *p);
extern void squid_getrusage(struct rusage *r);
extern double rusage_cputime(struct rusage *r);
extern int rusage_maxrss(struct rusage *r);
extern int rusage_pagefaults(struct rusage *r);

extern void unlinkdInit(void);
extern void unlinkdClose(void);
extern void unlinkdUnlink(const char *);

extern char *url_convert_hex(char *org_url, int allocate);
extern char *url_escape(const char *url);
extern protocol_t urlParseProtocol(const char *);
extern method_t urlParseMethod(const char *);
extern void urlInitialize(void);
extern request_t *urlParse(method_t, char *);
extern char *urlCanonical(const request_t *, char *);
extern request_t *requestLink(request_t *);
extern void requestUnlink(request_t *);
extern int matchDomainName(const char *d, const char *h);
extern int urlCheckRequest(const request_t *);
extern int urlDefaultPort(protocol_t p);
extern char *urlClean(char *);
extern char *urlCanonicalClean(const request_t *);

extern void useragentOpenLog(void);
extern void useragentRotateLog(void);
extern void logUserAgent(const char *, const char *);
extern peer_t parseNeighborType(const char *s);

extern void errorSend(int fd, ErrorState *);
extern void errorAppendEntry(StoreEntry *, ErrorState *);
extern void errorInitialize(void);
extern void errorFree(void);
extern ErrorState *errorCon(err_type, http_status);

extern OBJH stat_io_get;
extern OBJH stat_objects_get;
extern OBJH stat_vmobjects_get;
extern OBJH stat_utilization_get;
extern OBJH statFiledescriptors;
extern OBJH log_enable;
extern OBJH info_get;
extern OBJH server_list;
extern OBJH neighborDumpNonPeers;
extern OBJH dump_config;
extern OBJH storeDirStats;
extern OBJH pconnHistDump;
extern void dump_peers(StoreEntry *, peer *);
extern OBJH statAvg5min;
extern OBJH statAvg60min;

extern void pconnPush(int, const char *host, u_short port);
extern int pconnPop(const char *host, u_short port);
extern void pconnInit(void);

extern int asnMatchIp(void *, struct in_addr);
extern void asnCleanup(void);
extern void asnAclInitialize(acl *);
extern void asnInit(void);
extern void asnFreeMemory(void);
extern void dlinkAdd(void *data, dlink_node *, dlink_list *);
extern void dlinkDelete(dlink_node * m, dlink_list * list);
extern void kb_incr(kb_t *, size_t);

/*
 * prototypes for system functions missing from system includes
 */

#ifdef _SQUID_SOLARIS_
int getrusage(int, struct rusage *);
int getpagesize(void);
int gethostname(char *, int);
#endif

extern int ipcCreate(int type,
    const char *prog,
    char *const args[],
    const char *name,
    int *rfd,
    int *wfd);

extern int handleConnectionHeader(int, char *, char *);
