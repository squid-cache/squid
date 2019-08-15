/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SQUIDCONFIG_H_
#define SQUID_SQUIDCONFIG_H_

#include "acl/forward.h"
#include "base/RefCount.h"
#include "base/YesNoNone.h"
#if USE_DELAY_POOLS
#include "ClientDelayConfig.h"
#include "DelayConfig.h"
#endif
#include "helper/ChildConfig.h"
#include "HttpHeaderTools.h"
#include "ip/Address.h"
#if USE_DELAY_POOLS
#include "MessageDelayPools.h"
#endif
#include "Notes.h"
#include "security/forward.h"
#include "SquidTime.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif
#include "store/Disk.h"
#include "store/forward.h"

#if USE_OPENSSL
class sslproxy_cert_sign;
class sslproxy_cert_adapt;
#endif

namespace Mgr
{
class ActionPasswordList;
} // namespace Mgr
class CachePeer;
class CustomLog;
class CpuAffinityMap;
class external_acl;
class HeaderManglers;
class RefreshPattern;
class RemovalPolicySettings;

namespace AnyP
{
class PortCfg;
}

namespace Store {
class DiskConfig {
public:
    DiskConfig() { assert(swapDirs == nullptr); }
    ~DiskConfig() { delete[] swapDirs; }

    RefCount<SwapDir> *swapDirs = nullptr;
    int n_allocated = 0;
    int n_configured = 0;
    /// number of disk processes required to support all cache_dirs
    int n_strands = 0;
};
#define INDEXSD(i) (Config.cacheSwap.swapDirs[i].getRaw())
}

/// the representation of the configuration. POD.
class SquidConfig
{
public:
    struct {
        /* These should be for the Store::Root instance.
        * this needs pluggable parsing to be done smoothly.
        */
        int highWaterMark;
        int lowWaterMark;
    } Swap;

    YesNoNone memShared; ///< whether the memory cache is shared among workers
    YesNoNone shmLocking; ///< shared_memory_locking
    size_t memMaxSize;

    struct {
        int64_t min;
        int pct;
        int64_t max;
    } quickAbort;
    int64_t readAheadGap;
    RemovalPolicySettings *replPolicy;
    RemovalPolicySettings *memPolicy;
#if USE_HTTP_VIOLATIONS
    time_t negativeTtl;
#endif
    time_t maxStale;
    time_t negativeDnsTtl;
    time_t positiveDnsTtl;
    time_t shutdownLifetime;
    time_t backgroundPingRate;
    time_t hopelessKidRevivalDelay; ///< hopeless_kid_revival_delay

    struct {
        time_t read;
        time_t write;
        time_t lifetime;
        time_t connect;
        time_t forward;
        time_t peer_connect;
        time_t request;
        time_t clientIdlePconn;
        time_t serverIdlePconn;
        time_t ftpClientIdle;
        time_t pconnLifetime; ///< pconn_lifetime in squid.conf
        time_t siteSelect;
        time_t deadPeer;
        time_t request_start_timeout;
        int icp_query;      /* msec */
        int icp_query_max;  /* msec */
        int icp_query_min;  /* msec */
        int mcast_icp_query;    /* msec */
        time_msec_t idns_retransmit;
        time_msec_t idns_query;
        time_t urlRewrite;
    } Timeout;
    size_t maxRequestHeaderSize;
    int64_t maxRequestBodySize;
    size_t maxRequestBufferSize;
    size_t maxReplyHeaderSize;
    AclSizeLimit *ReplyBodySize;

    struct {
        unsigned short icp;
#if USE_HTCP

        unsigned short htcp;
#endif
#if SQUID_SNMP

        unsigned short snmp;
#endif
    } Port;

#if SQUID_SNMP

    struct {
        char *configFile;
        char *agentInfo;
    } Snmp;
#endif
#if USE_WCCP

    struct {
        Ip::Address router;
        Ip::Address address;
        int version;
    } Wccp;
#endif
#if USE_WCCPv2

    struct {
        Ip::Address_list *router;
        Ip::Address address;
        int forwarding_method;
        int return_method;
        int assignment_method;
        int weight;
        int rebuildwait;
        void *info;
    } Wccp2;
#endif

    char *as_whois_server;

    struct {
        char *store;
        char *swap;
        CustomLog *accesslogs;
#if ICAP_CLIENT
        CustomLog *icaplogs;
#endif
        int rotateNumber;
    } Log;
    char *adminEmail;
    char *EmailFrom;
    char *EmailProgram;
    char *effectiveUser;
    char *visible_appname_string;
    char *effectiveGroup;

    struct {
        wordlist *redirect;
        wordlist *store_id;
#if USE_UNLINKD

        char *unlinkd;
#endif

        char *diskd;
#if USE_OPENSSL

        char *ssl_password;
#endif

    } Program;

    Helper::ChildConfig redirectChildren;
    Helper::ChildConfig storeIdChildren;

    struct {
        char *surrogate_id;
    } Accel;
    char *appendDomain;
    size_t appendDomainLen;
    char *pidFilename;
    char *netdbFilename;
    char *mimeTablePathname;
    char *etcHostsPath;
    char *visibleHostname;
    char *uniqueHostname;
    wordlist *hostnameAliases;
    char *errHtmlText;

    struct {
        char *host;
        char *file;
        time_t period;
        unsigned short port;
    } Announce;

    struct {

        Ip::Address udp_incoming;
        Ip::Address udp_outgoing;
#if SQUID_SNMP
        Ip::Address snmp_incoming;
        Ip::Address snmp_outgoing;
#endif
        /* FIXME INET6 : this should really be a CIDR value */
        Ip::Address client_netmask;
    } Addrs;
    size_t tcpRcvBufsz;
    size_t udpMaxHitObjsz;
    wordlist *mcast_group_list;
    CachePeer *peers;
    int npeers;

    struct {
        int size;
        int low;
        int high;
    } ipcache;

    struct {
        int size;
    } fqdncache;
    int minDirectHops;
    int minDirectRtt;
    Mgr::ActionPasswordList *passwd_list;

    struct {
        int objectsPerBucket;
        int64_t avgObjectSize;
        int64_t maxObjectSize;
        int64_t minObjectSize;
        size_t maxInMemObjSize;
    } Store;

    struct {
        int high;
        int low;
        time_t period;
    } Netdb;

    struct {
        int log_udp;
        int res_defnames;
        int anonymizer;
        int client_db;
        int query_icmp;
        int icp_hit_stale;
        int buffered_logs;
        int common_log;
        int log_mime_hdrs;
        int log_fqdn;
        int announce;
        int mem_pools;
        int test_reachability;
        int half_closed_clients;
        int refresh_all_ims;
#if USE_HTTP_VIOLATIONS

        int reload_into_ims;
#endif

        int offline;
        int redir_rewrites_host;
        int prefer_direct;
        int nonhierarchical_direct;
        int strip_query_terms;
        int redirector_bypass;
        int store_id_bypass;
        int ignore_unknown_nameservers;
        int client_pconns;
        int server_pconns;
        int error_pconns;
#if USE_CACHE_DIGESTS

        int digest_generation;
#endif

        int vary_ignore_expire;
        int surrogate_is_remote;
        int request_entities;
        int detect_broken_server_pconns;
        int relaxed_header_parser;
        int check_hostnames;
        int allow_underscore;
        int via;
        int cache_miss_revalidate;
        int emailErrData;
        int httpd_suppress_version_string;
        int global_internal_static;
        int collapsed_forwarding;

#if FOLLOW_X_FORWARDED_FOR
        int acl_uses_indirect_client;
        int delay_pool_uses_indirect_client;
        int log_uses_indirect_client;
#if LINUX_NETFILTER
        int tproxy_uses_indirect_client;
#endif
#endif /* FOLLOW_X_FORWARDED_FOR */

        int WIN32_IpAddrChangeMonitor;
        int memory_cache_first;
        int memory_cache_disk;
        int hostStrictVerify;
        int client_dst_passthru;
        int dns_mdns;
#if USE_OPENSSL
        bool logTlsServerHelloDetails;
#endif
    } onoff;

    int64_t shared_transient_entries_limit;

    int pipeline_max_prefetch;

    int forward_max_tries;
    int connect_retries;

    class ACL *aclList;

    struct {
        acl_access *http;
        acl_access *adapted_http;
        acl_access *icp;
        acl_access *miss;
        acl_access *NeverDirect;
        acl_access *AlwaysDirect;
        acl_access *ASlists;
        acl_access *noCache;
        acl_access *sendHit;
        acl_access *storeMiss;
        acl_access *stats_collection;
#if SQUID_SNMP

        acl_access *snmp;
#endif
#if USE_HTTP_VIOLATIONS
        acl_access *brokenPosts;
#endif
        acl_access *redirector;
        acl_access *store_id;
        acl_access *reply;
        Acl::Address *outgoing_address;
#if USE_HTCP

        acl_access *htcp;
        acl_access *htcp_clr;
#endif

#if USE_OPENSSL
        acl_access *ssl_bump;
#endif
#if FOLLOW_X_FORWARDED_FOR
        acl_access *followXFF;
#endif /* FOLLOW_X_FORWARDED_FOR */

        /// acceptible PROXY protocol clients
        acl_access *proxyProtocol;

        /// spoof_client_ip squid.conf acl.
        /// nil unless configured
        acl_access* spoof_client_ip;
        acl_access *on_unsupported_protocol;

        acl_access *ftp_epsv;

        acl_access *forceRequestBodyContinuation;
        acl_access *serverPconnForNonretriable;
        acl_access *collapsedForwardingAccess;
    } accessList;
    AclDenyInfoList *denyInfoList;

    struct {
        size_t list_width;
        int list_wrap;
        char *anon_user;
        int passive;
        int epsv_all;
        int epsv;
        int eprt;
        int sanitycheck;
        int telnet;
    } Ftp;
    RefreshPattern *Refresh;

    Store::DiskConfig cacheSwap;

    struct {
        char *directory;
        int use_short_names;
    } icons;
    char *errorDirectory;
#if USE_ERR_LOCALES
    char *errorDefaultLanguage;
    int errorLogMissingLanguages;
#endif
    char *errorStylesheet;

    struct {
        int onerror;
    } retry;

    struct {
        int64_t limit;
    } MemPools;
#if USE_DELAY_POOLS

    DelayConfig Delay;
    ClientDelayConfig ClientDelay;
    MessageDelayConfig MessageDelay;
#endif

    struct {
        struct {
            int average;
            int min_poll;
        } dns, udp, tcp;
    } comm_incoming;
    int max_open_disk_fds;
    int uri_whitespace;
    AclSizeLimit *rangeOffsetLimit;
#if MULTICAST_MISS_STREAM

    struct {

        Ip::Address addr;
        int ttl;
        unsigned short port;
        char *encode_key;
    } mcast_miss;
#endif

    /// request_header_access and request_header_replace
    HeaderManglers *request_header_access;
    /// reply_header_access and reply_header_replace
    HeaderManglers *reply_header_access;
    ///request_header_add access list
    HeaderWithAclList *request_header_add;
    ///reply_header_add access list
    HeaderWithAclList *reply_header_add;
    ///note
    Notes notes;
    char *coredump_dir;
    char *chroot_dir;
#if USE_CACHE_DIGESTS

    struct {
        int bits_per_entry;
        time_t rebuild_period;
        time_t rewrite_period;
        size_t swapout_chunk_size;
        int rebuild_chunk_percentage;
    } digest;
#endif
#if USE_OPENSSL

    struct {
        int unclean_shutdown;
        char *ssl_engine;
        int session_ttl;
        size_t sessionCacheSize;
        char *certSignHash;
    } SSL;
#endif

    struct {
        int high_rptm;
        int high_pf;
        size_t high_memory;
    } warnings;
    char *store_dir_select_algorithm;
    int sleep_after_fork;   /* microseconds */
    time_t minimum_expiry_time; /* seconds */
    external_acl *externalAclHelperList;

    struct {
        Security::ContextPointer sslContext;
#if USE_OPENSSL
        char *foreignIntermediateCertsPath;
        acl_access *cert_error;
        sslproxy_cert_sign *cert_sign;
        sslproxy_cert_adapt *cert_adapt;
#endif
    } ssl_client;

    char *accept_filter;
    int umask;
    int max_filedescriptors;
    int workers;
    CpuAffinityMap *cpuAffinityMap;

#if USE_LOADABLE_MODULES
    wordlist *loadable_module_names;
#endif

    int client_ip_max_connections;

    char *redirector_extras;

    struct UrlHelperTimeout {
        int action;
        char *response;
    } onUrlRewriteTimeout;

    char *storeId_extras;

    struct {
        SBufList nameservers;
        int v4_first;       ///< Place IPv4 first in the order of DNS results.
        ssize_t packet_max; ///< maximum size EDNS advertised for DNS replies.
    } dns;

    struct {
        int connect_limit;
        int connect_gap;
        int connect_timeout;
    } happyEyeballs;
};

extern SquidConfig Config;

class SquidConfig2
{
public:
    void clear() {
        *this = SquidConfig2();
    }

    struct {
        int enable_purge = 0;
    } onoff;
    uid_t effectiveUserID = 0;
    gid_t effectiveGroupID = 0;
};

extern SquidConfig2 Config2;

#endif /* SQUID_SQUIDCONFIG_H_ */

