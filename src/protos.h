

extern void accessLogLog _PARAMS((AccessLogEntry *));
extern void accessLogRotate _PARAMS((void));
extern void accessLogClose _PARAMS((void));
extern void accessLogOpen _PARAMS((const char *));
extern void hierarchyNote _PARAMS((HierarchyLogEntry *, hier_code, icp_ping_data *, const char *));

extern aclCheck_t *aclChecklistCreate _PARAMS((const struct _acl_access *,
	request_t *,
	struct in_addr src,
	char *ua,
	char *id));
extern void aclNBCheck _PARAMS((aclCheck_t *, PF *, void *));
extern int aclCheckFast _PARAMS((const struct _acl_access * A, aclCheck_t *));
extern void aclChecklistFree _PARAMS((aclCheck_t *));
extern int aclMatchAcl _PARAMS((struct _acl *, aclCheck_t *));
extern void aclDestroyAccessList _PARAMS((struct _acl_access ** list));
extern void aclDestroyAcls _PARAMS((acl **));
extern void aclParseAccessLine _PARAMS((struct _acl_access **));
extern void aclParseAclLine _PARAMS((acl **));
extern struct _acl *aclFindByName _PARAMS((const char *name));
extern char *aclGetDenyInfoUrl _PARAMS((struct _acl_deny_info_list **, const char *name));
extern void aclParseDenyInfoLine _PARAMS((struct _acl_deny_info_list **));
extern void aclDestroyDenyInfoList _PARAMS((struct _acl_deny_info_list **));
extern void aclDestroyRegexList _PARAMS((struct _relist * data));
extern int aclMatchRegex _PARAMS((relist * data, const char *word));
extern void aclParseRegexList _PARAMS((void *curlist));


extern int aio_cancel _PARAMS((aio_result_t *));
extern int aio_open _PARAMS((const char *, int, mode_t, aio_result_t *));
extern int aio_read _PARAMS((int, char *, int, off_t, int, aio_result_t *));
extern int aio_write _PARAMS((int, char *, int, off_t, int, aio_result_t *));
extern int aio_close _PARAMS((int, aio_result_t *));
extern int aio_stat _PARAMS((const char *, struct stat *, aio_result_t *));
extern int aio_unlink _PARAMS((const char *, aio_result_t *));
extern int aio_opendir _PARAMS((void));
extern aio_result_t *aio_poll_done _PARAMS((void));


extern void aioCancel _PARAMS((int));
extern void aioOpen _PARAMS((const char *, int, mode_t, AIOCB *, void *));
extern void aioClose _PARAMS((int));
extern void aioWrite _PARAMS((int, char *, int, AIOCB *, void *));
extern void aioRead _PARAMS((int, char *, int, AIOCB *, void *));
extern void aioStat _PARAMS((char *, struct stat *, AIOCB *, void *));
extern void aioUnlink _PARAMS((const char *, AIOCB *, void *));
extern void aioCheckCallbacks _PARAMS((void));

extern int parseConfigFile _PARAMS((const char *file_name));
extern void intlistDestroy _PARAMS((intlist **));
extern void wordlistDestroy _PARAMS((wordlist **));
extern void configFreeMemory _PARAMS((void));
extern void dump_all _PARAMS((void));

extern void cbdataInit _PARAMS((void));
extern void cbdataAdd _PARAMS((void *p));
extern void cbdataFree _PARAMS((void *p));
extern void cbdataLock _PARAMS((void *p));
extern void cbdataUnlock _PARAMS((void *p));
extern int cbdataValid _PARAMS((void *p));
extern void cbdataDump _PARAMS((StoreEntry *));

extern void clientdbInit _PARAMS((void));
extern void clientdbUpdate _PARAMS((struct in_addr, log_type, protocol_t));
extern int clientdbDeniedPercent _PARAMS((struct in_addr));
extern void clientdbDump _PARAMS((StoreEntry *));
extern CWCB clientWriteComplete;

extern void clientAccessCheck _PARAMS((void *));
extern void clientAccessCheckDone _PARAMS((int, void *));
extern void icpProcessExpired _PARAMS((int fd, void *));
extern int modifiedSince _PARAMS((StoreEntry *, request_t *));
extern char *clientConstructTraceEcho _PARAMS((clientHttpRequest *));
extern void clientPurgeRequest _PARAMS((clientHttpRequest *));

#if USE_PROXY_AUTH
extern const char *proxyAuthenticate(const char *headers);
#endif /* USE_PROXY_AUTH */


extern int commSetNonBlocking _PARAMS((int fd));
extern void commSetCloseOnExec _PARAMS((int fd));
extern int comm_accept _PARAMS((int fd, struct sockaddr_in *, struct sockaddr_in *));
extern void comm_close _PARAMS((int fd));
extern void commConnectStart _PARAMS((int fd, const char *, u_short, CNCB *, void *));
extern int comm_connect_addr _PARAMS((int sock, const struct sockaddr_in *));
extern int comm_init _PARAMS((void));
extern int comm_listen _PARAMS((int sock));
extern int comm_open _PARAMS((int, int, struct in_addr, u_short port, int, const char *note));
extern u_short comm_local_port _PARAMS((int fd));
#if HAVE_POLL
extern int comm_poll _PARAMS((time_t));
#else
extern int comm_select _PARAMS((time_t));
#endif
extern void commSetSelect _PARAMS((int, unsigned int, PF *, void *, time_t));
extern void comm_add_close_handler _PARAMS((int fd, PF *, void *));
extern void comm_remove_close_handler _PARAMS((int fd, PF *, void *));
extern int comm_udp_send _PARAMS((int fd, const char *host, u_short port, const char *buf, int len));
extern int comm_udp_sendto _PARAMS((int fd, const struct sockaddr_in *, int size, const char *buf, int len));
extern void comm_set_stall _PARAMS((int, int));
extern void comm_write _PARAMS((int fd,
	char *buf,
	int size,
	CWCB * handler,
	void *handler_data,
	FREE *));
extern void commCallCloseHandlers _PARAMS((int fd));
extern void commCancelWriteHandler _PARAMS((int fd));
extern int commSetTimeout _PARAMS((int fd, int, PF *, void *));

extern void _db_init _PARAMS((const char *logfile, const char *options));
extern void _db_rotate_log _PARAMS((void));

#ifdef __STDC__
extern void _db_print _PARAMS((const char *,...));
#else
extern void _db_print _PARAMS(());
#endif


extern int file_open _PARAMS((const char *path, int mode, FOCB *, void *callback_data));
extern void file_close _PARAMS((int fd));
extern int file_write _PARAMS((int fd,
	char *buf,
	int len,
	DWCB * handle,
	void *handle_data,
	FREE *));
extern int file_read _PARAMS((int fd,
	char *buf,
	int req_len,
	int offset,
	DRCB * handler,
	void *client_data));
extern int file_walk _PARAMS((int fd, FILE_WALK_HD *, void *, FILE_WALK_LHD *, void *));
extern int disk_init _PARAMS((void));
extern int diskWriteIsComplete _PARAMS((int));

extern void dnsShutdownServers _PARAMS((void));
extern void dnsOpenServers _PARAMS((void));
extern dnsserver_t *dnsGetFirstAvailable _PARAMS((void));
extern void dnsStats _PARAMS((StoreEntry *));
extern void dnsFreeMemory _PARAMS((void));

extern char *squid_error_url _PARAMS((const char *, int, int, const char *, int, const char *));
extern char *squid_error_request _PARAMS((const char *, int, int));
extern char *access_denied_msg _PARAMS((int, int, const char *, const char *));
extern char *access_denied_redirect _PARAMS((int, int, const char *, const char *, const char *));
#if USE_PROXY_AUTH
extern char *proxy_denied_msg _PARAMS((int, int, const char *, const char *));
#endif /* USE_PROXY_AUTH */
extern char *authorization_needed_msg _PARAMS((const request_t *, const char *));
extern void errorpageFreeMemory _PARAMS((void));


extern void eventAdd _PARAMS((const char *name,
	EVH * func,
	void *arg,
	time_t when));
extern void eventRun _PARAMS((void));
extern time_t eventNextTime _PARAMS((void));
extern void eventDelete _PARAMS((EVH * func, void *arg));

extern void fd_close _PARAMS((int fd));
extern void fd_open _PARAMS((int fd, unsigned int type, const char *));
extern void fd_note _PARAMS((int fd, const char *));
extern void fd_bytes _PARAMS((int fd, int len, unsigned int type));
extern void fdFreeMemory _PARAMS((void));
extern void fdDumpOpen _PARAMS((void));

extern void fdstat_init _PARAMS((void));
extern int fdstat_are_n_free_fd _PARAMS((int));

extern fileMap *file_map_create _PARAMS((int));
extern int file_map_allocate _PARAMS((fileMap *, int));
extern int file_map_bit_set _PARAMS((fileMap *, int));
extern int file_map_bit_test _PARAMS((fileMap *, int));
extern void file_map_bit_reset _PARAMS((fileMap *, int));
extern void filemapFreeMemory _PARAMS((fileMap *));


extern void fqdncache_nbgethostbyaddr _PARAMS((struct in_addr, FQDNH *, void *));
extern int fqdncacheUnregister _PARAMS((struct in_addr, void *));
extern const char *fqdncache_gethostbyaddr _PARAMS((struct in_addr, int flags));
extern void fqdncache_init _PARAMS((void));
extern void fqdnStats _PARAMS((StoreEntry *));
extern void fqdncacheReleaseInvalid _PARAMS((const char *));
extern const char *fqdnFromAddr _PARAMS((struct in_addr));
extern int fqdncacheQueueDrain _PARAMS((void));
extern void fqdncacheFreeMemory _PARAMS((void));
extern void fqdncache_restart _PARAMS((void));

extern void ftpStart _PARAMS((request_t * req, StoreEntry * entry));

extern void gopherStart _PARAMS((StoreEntry *));
extern int gopherCachable _PARAMS((const char *));


/* init */
extern hash_table *hash_create _PARAMS((HASHCMP *, int, HASHHASH *));
extern int hash_insert _PARAMS((hash_table *, const char *, void *));
extern int hash_delete _PARAMS((hash_table *, const char *));
extern int hash_delete_link _PARAMS((hash_table *, hash_link *));
extern int hash_join _PARAMS((hash_table *, hash_link *));
extern int hash_remove_link _PARAMS((hash_table *, hash_link *));

/* searching, accessing */
extern hash_link *hash_lookup _PARAMS((hash_table *, const char *));
extern hash_link *hash_first _PARAMS((hash_table *));
extern hash_link *hash_next _PARAMS((hash_table *));
extern hash_link *hash_get_bucket _PARAMS((hash_table *, unsigned int));
extern void hashFreeMemory _PARAMS((hash_table *));
extern HASHHASH hash_string;
extern HASHHASH hash_url;
extern HASHHASH hash4;

extern int httpCachable _PARAMS((method_t));
extern void httpStart _PARAMS((request_t *, StoreEntry *, peer *));
extern void httpParseReplyHeaders _PARAMS((const char *, struct _http_reply *));
extern void httpProcessReplyHeader _PARAMS((HttpStateData *, const char *, int));
extern void httpReplyHeaderStats _PARAMS((StoreEntry *));
extern size_t httpBuildRequestHeader _PARAMS((request_t * request,
	request_t * orig_request,
	StoreEntry * entry,
	size_t * in_len,
	char *hdr_out,
	size_t out_sz,
	int cfd,
	int flags));
extern int httpAnonAllowed _PARAMS((const char *line));
extern int httpAnonDenied _PARAMS((const char *line));
extern char *httpReplyHeader _PARAMS((double ver,
	http_status status,
	char *ctype,
	int clen,
	time_t lmt,
	time_t expires));


extern void icmpOpen _PARAMS((void));
extern void icmpClose _PARAMS((void));
extern void icmpPing _PARAMS((struct in_addr to));
extern void icmpSourcePing _PARAMS((struct in_addr to, const icp_common_t *, const char *url));
extern void icmpDomainPing _PARAMS((struct in_addr to, const char *domain));


extern void *icpCreateMessage _PARAMS((icp_opcode opcode,
	int flags,
	const char *url,
	int reqnum,
	int pad));
extern void icpUdpSend _PARAMS((int fd,
	const struct sockaddr_in *,
	icp_common_t * msg,
	log_type,
	protocol_t));
extern PF icpHandleUdp;
extern PF httpAccept;
extern void icpSendERROR _PARAMS((int fd,
	log_type errorCode,
	const char *text,
	clientHttpRequest *,
	int httpCode));
extern void AppendUdp _PARAMS((icpUdpData *));
extern void icpParseRequestHeaders _PARAMS((clientHttpRequest *));
extern void icpProcessRequest _PARAMS((int, clientHttpRequest *));
extern PF icpUdpReply;
extern ERCB icpErrorComplete;
extern STCB icpSendMoreData;


extern void ipcache_nbgethostbyname _PARAMS((const char *name,
	IPH * handler,
	void *handlerData));
extern EVH ipcache_purgelru;
extern const ipcache_addrs *ipcache_gethostbyname _PARAMS((const char *, int flags));
extern void ipcacheInvalidate _PARAMS((const char *));
extern void ipcacheReleaseInvalid _PARAMS((const char *));
extern void ipcacheShutdownServers _PARAMS((void));
extern void ipcache_init _PARAMS((void));
extern void stat_ipcache_get _PARAMS((StoreEntry *));
extern int ipcacheQueueDrain _PARAMS((void));
extern void ipcacheCycleAddr _PARAMS((const char *name));
extern void ipcacheRemoveBadAddr _PARAMS((const char *name, struct in_addr));
extern void ipcacheFreeMemory _PARAMS((void));
extern ipcache_addrs *ipcacheCheckNumeric _PARAMS((const char *name));
extern void ipcache_restart _PARAMS((void));
extern int ipcacheUnregister _PARAMS((const char *name, void *data));

extern char *mime_get_header _PARAMS((const char *mime, const char *header));
extern char *mime_headers_end _PARAMS((const char *mime));
extern int mk_mime_hdr _PARAMS((char *result, const char *type, int size, time_t ttl, time_t lmt));
extern void mimeInit _PARAMS((char *filename));
extern char *mimeGetContentEncoding _PARAMS((const char *fn));
extern char *mimeGetContentType _PARAMS((const char *fn));
extern char *mimeGetIcon _PARAMS((const char *fn));
extern char mimeGetTransferMode _PARAMS((const char *fn));

extern int mcastSetTtl _PARAMS((int, int));
extern IPH mcastJoinGroups;

/* Labels for hierachical log file */
/* put them all here for easier reference when writing a logfile analyzer */


extern peer *getFirstPeer _PARAMS((void));
extern peer *getFirstUpParent _PARAMS((request_t *));
extern peer *getNextPeer _PARAMS((peer *));
extern peer *getSingleParent _PARAMS((request_t *));
extern int neighborsCount _PARAMS((request_t *));
extern int neighborsUdpPing _PARAMS((request_t *,
	StoreEntry *,
	IRCB * callback,
	void *data,
	int *exprep));
extern void neighborAddAcl _PARAMS((const char *, const char *));
extern void neighborsUdpAck _PARAMS((int, const char *, icp_common_t *, const struct sockaddr_in *, StoreEntry *, char *, int));
extern void neighborAdd _PARAMS((const char *, const char *, int, int, int, int, int));
extern void neighbors_open _PARAMS((int));
extern peer *peerFindByName _PARAMS((const char *));
extern peer *getDefaultParent _PARAMS((request_t * request));
extern peer *getRoundRobinParent _PARAMS((request_t * request));
extern int neighborUp _PARAMS((const peer * e));
extern void peerDestroy _PARAMS((peer * e));
extern char *neighborTypeStr _PARAMS((const peer * e));
extern void peerCheckConnectStart _PARAMS((peer *));

extern void netdbHandlePingReply _PARAMS((const struct sockaddr_in * from, int hops, int rtt));
extern void netdbPingSite _PARAMS((const char *hostname));
extern void netdbInit _PARAMS((void));
extern void netdbDump _PARAMS((StoreEntry *));
extern int netdbHops _PARAMS((struct in_addr));
extern void netdbFreeMemory _PARAMS((void));
extern int netdbHostHops _PARAMS((const char *host));
extern int netdbHostRtt _PARAMS((const char *host));
extern void netdbUpdatePeer _PARAMS((request_t *, peer * e, int rtt, int hops));

extern void objcachePasswdAdd _PARAMS((cachemgr_passwd **, char *, wordlist *));
extern void objcachePasswdDestroy _PARAMS((cachemgr_passwd ** a));
extern void objcacheStart _PARAMS((int fd, StoreEntry *));
extern void objcacheInit _PARAMS((void));

extern void peerSelect _PARAMS((request_t *, StoreEntry *, PSC *, PSC *, void *data));
extern peer *peerGetSomeParent _PARAMS((request_t *, hier_code *));
extern void peerSelectInit _PARAMS((void));

extern void protoDispatch _PARAMS((int, StoreEntry *, request_t *));

extern int protoUnregister _PARAMS((StoreEntry *, request_t *, struct in_addr));
extern void protoStart _PARAMS((int, StoreEntry *, peer *, request_t *));
extern int protoAbortFetch _PARAMS((StoreEntry * entry));


extern void redirectStart _PARAMS((clientHttpRequest *, RH *, void *));
extern void redirectOpenServers _PARAMS((void));
extern void redirectShutdownServers _PARAMS((void));
extern void redirectStats _PARAMS((StoreEntry *));
extern int redirectUnregister _PARAMS((const char *url, void *));
extern void redirectFreeMemory _PARAMS((void));

extern void refreshAddToList _PARAMS((const char *, int, time_t, int, time_t));
extern int refreshCheck _PARAMS((const StoreEntry *, const request_t *, time_t delta));
extern time_t getMaxAge _PARAMS((const char *url));



extern void serverConnectionsClose _PARAMS((void));
extern void shut_down _PARAMS((int));


extern void start_announce _PARAMS((void *unused));
extern void sslStart _PARAMS((int fd, const char *, request_t *, size_t * sz));
extern void waisStart _PARAMS((request_t *, StoreEntry *));
extern void storeDirClean _PARAMS((void *unused));
extern void passStart _PARAMS((int, const char *, request_t *, size_t *));
extern void identStart _PARAMS((int, ConnStateData *, IDCB * callback));

extern void *pop _PARAMS((Stack *));
extern int empty_stack _PARAMS((const Stack *));
extern int full_stack _PARAMS((const Stack *));
extern void push _PARAMS((Stack *, void *));
extern void init_stack _PARAMS((Stack *, int));
extern void stackFreeMemory _PARAMS((Stack *));

extern void stat_init _PARAMS((cacheinfo **, const char *));
extern void pconnHistCount _PARAMS((int, int));

/* To reduce memory fragmentation, we now store the memory version of an
 * object in fixed size blocks of size PAGE_SIZE and instead of calling 
 * malloc and free, we manage our own fixed block free list.   
 */

extern char *get_free_4k_page _PARAMS((void));
extern char *get_free_8k_page _PARAMS((void));
extern void *get_free_request_t _PARAMS((void));
extern void *get_free_mem_obj _PARAMS((void));
extern mem_hdr *memInit _PARAMS((void));
extern void put_free_4k_page _PARAMS((void *));
extern void put_free_8k_page _PARAMS((void *));
extern void put_free_request_t _PARAMS((void *));
extern void put_free_mem_obj _PARAMS((void *));
extern void stmemInit _PARAMS((void));
extern void stmemFreeMemory _PARAMS((void));

extern int memFreeDataUpto _PARAMS((mem_hdr *, int));
extern void memAppend _PARAMS((mem_hdr *, const char *, int));
extern ssize_t memCopy _PARAMS((const mem_hdr *, off_t, char *, size_t));
extern void memFree _PARAMS((mem_hdr *));
extern void memFreeData _PARAMS((mem_hdr *));



/* ----------------------------------------------------------------- */

extern StoreEntry *storeGet _PARAMS((const char *));
extern StoreEntry *storeCreateEntry _PARAMS((const char *, const char *, int, method_t));
extern void storeSetPublicKey _PARAMS((StoreEntry *));
extern StoreEntry *storeGetFirst _PARAMS((void));
extern StoreEntry *storeGetNext _PARAMS((void));
extern void storeComplete _PARAMS((StoreEntry *));
extern void storeInit _PARAMS((void));
extern int storeClientWaiting _PARAMS((const StoreEntry *));
extern void storeAbort _PARAMS((StoreEntry *, int));
extern void storeAppend _PARAMS((StoreEntry *, const char *, int));
extern int storeGetSwapSpace _PARAMS((int));
extern void storeLockObject _PARAMS((StoreEntry *));
extern void storeSwapInStart _PARAMS((StoreEntry *, SIH *, void *data));
extern int storeRelease _PARAMS((StoreEntry *));
extern int storeUnlockObject _PARAMS((StoreEntry *));
extern int storeUnregister _PARAMS((StoreEntry *, void *));
extern const char *storeGeneratePublicKey _PARAMS((const char *, method_t));
extern const char *storeGeneratePrivateKey _PARAMS((const char *, method_t, int));
extern void storeStartDeleteBehind _PARAMS((StoreEntry *));
extern void storeClientCopy _PARAMS((StoreEntry * e,
	off_t seen_offset,
	off_t copy_offset,
	size_t size,
	char *buf,
	STCB * callback,
	void *data));
extern int storePendingNClients _PARAMS((const StoreEntry *));
extern int storeWriteCleanLogs _PARAMS((void));
extern HASHCMP urlcmp;
extern EVH storeMaintainSwapSpace;
extern void storeExpireNow _PARAMS((StoreEntry *));
extern void storeReleaseRequest _PARAMS((StoreEntry *));
extern void storeRotateLog _PARAMS((void));
extern int storeGetLowestReaderOffset _PARAMS((const StoreEntry *));
extern void storeCloseLog _PARAMS((void));
extern void storeConfigure _PARAMS((void));
extern void storeNegativeCache _PARAMS((StoreEntry *));
extern void storeFreeMemory _PARAMS((void));
extern int expiresMoreThan _PARAMS((time_t, time_t));
extern int storeClientListAdd _PARAMS((StoreEntry *, void *));
extern void InvokeHandlers _PARAMS((const StoreEntry *));
extern int storeEntryValidToSend _PARAMS((StoreEntry *));
extern void storeTimestampsSet _PARAMS((StoreEntry *));
extern unsigned int storeReqnum _PARAMS((StoreEntry * entry, method_t));
extern time_t storeExpiredReferenceAge _PARAMS((void));
extern void storeRegisterAbort _PARAMS((StoreEntry * e, STABH * cb, void *));
extern void storeUnregisterAbort _PARAMS((StoreEntry * e));
extern void storeMemObjectDump _PARAMS((MemObject * mem));

#ifdef __STDC__
extern void storeAppendPrintf _PARAMS((StoreEntry *, const char *,...));
#else
extern void storeAppendPrintf _PARAMS(());
#endif

extern char *storeSwapFullPath _PARAMS((int, char *));
extern char *storeSwapSubSubDir _PARAMS((int, char *));
extern int storeVerifySwapDirs _PARAMS((void));
extern void storeCreateSwapSubDirs _PARAMS((int));
extern const char *storeSwapPath _PARAMS((int));
extern int storeDirMapBitTest _PARAMS((int fn));
extern void storeDirMapBitSet _PARAMS((int fn));
extern void storeDirMapBitReset _PARAMS((int fn));
extern int storeDirMapAllocate _PARAMS((void));
extern char *storeSwapDir _PARAMS((int));
extern FILE *storeDirOpenTmpSwapLog _PARAMS((int dirn, int *clean_flag));
extern void storeDirCloseTmpSwapLog _PARAMS((int dirn));
extern void storeDirOpenSwapLogs _PARAMS((void));
extern void storeDirCloseSwapLogs _PARAMS((void));
extern char *storeDirSwapLogFile _PARAMS((int, const char *));
extern void storeDirSwapLog _PARAMS((const StoreEntry *));
extern int storeDirNumber _PARAMS((int fileno));
extern void storeDirUpdateSwapSize _PARAMS((int fn, size_t size, int sign));
extern int storeDirProperFileno _PARAMS((int dirn, int fn));


extern const char *getMyHostname _PARAMS((void));
extern void safeunlink _PARAMS((const char *path, int quiet));
extern void death _PARAMS((int sig));
extern void fatal _PARAMS((const char *message));
extern void fatal_dump _PARAMS((const char *message));
extern void sigusr2_handle _PARAMS((int sig));
extern void sig_child _PARAMS((int sig));
extern void leave_suid _PARAMS((void));
extern void enter_suid _PARAMS((void));
extern void no_suid _PARAMS((void));
extern void writePidFile _PARAMS((void));
extern void setSocketShutdownLifetimes _PARAMS((int));
extern void setMaxFD _PARAMS((void));
extern time_t getCurrentTime _PARAMS((void));
extern void normal_shutdown _PARAMS((void));
extern int percent _PARAMS((int, int));
extern void squid_signal _PARAMS((int sig, void (*func) _PARAMS((int)), int flags));
extern pid_t readPidFile _PARAMS((void));
extern struct in_addr inaddrFromHostent _PARAMS((const struct hostent * hp));
extern int intAverage _PARAMS((int, int, int, int));
extern double doubleAverage _PARAMS((double, double, int, int));
extern void debug_trap _PARAMS((const char *));
extern void logsFlush _PARAMS((void));
extern char *checkNullString _PARAMS((char *p));

extern void unlinkdInit _PARAMS((void));
extern void unlinkdClose _PARAMS((void));
extern void unlinkdUnlink _PARAMS((const char *));

extern char *url_convert_hex _PARAMS((char *org_url, int allocate));
extern char *url_escape _PARAMS((const char *url));
extern protocol_t urlParseProtocol _PARAMS((const char *));
extern method_t urlParseMethod _PARAMS((const char *));
extern void urlInitialize _PARAMS((void));
extern request_t *urlParse _PARAMS((method_t, char *));
extern char *urlCanonical _PARAMS((const request_t *, char *));
extern request_t *requestLink _PARAMS((const request_t *));
extern void requestUnlink _PARAMS((request_t *));
extern int matchDomainName _PARAMS((const char *d, const char *h));
extern int urlCheckRequest _PARAMS((const request_t *));
extern int urlDefaultPort _PARAMS((protocol_t p));
extern char *urlClean _PARAMS((char *));
extern char *urlCanonicalClean _PARAMS((const request_t *));


extern void useragentOpenLog _PARAMS((void));
extern void useragentRotateLog _PARAMS((void));
extern void logUserAgent _PARAMS((const char *, const char *));
extern peer_t parseNeighborType _PARAMS((const char *s));

extern void errorSend _PARAMS((int fd, ErrorState *));
extern void errorAppendEntry _PARAMS((const StoreEntry *, ErrorState *));
extern void errorInitialize _PARAMS((void));

extern OBJH stat_io_get;
extern OBJH stat_objects_get;
extern OBJH stat_vmobjects_get;
extern OBJH stat_utilization_get;
extern OBJH statFiledescriptors;
extern OBJH log_enable;
extern OBJH info_get;
extern OBJH server_list;
extern OBJH parameter_get;
extern OBJH storeDirStats;
extern OBJH pconnHistDump;

extern void pconnPush _PARAMS((int, const char *host, u_short port));
extern int pconnPop _PARAMS((const char *host, u_short port));
extern void pconnInit _PARAMS((void));
