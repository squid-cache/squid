/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 12    Internet Cache Protocol (ICP) */

/**
 \defgroup ServerProtocolICPInternal2 ICPv2 Internals
 \ingroup ServerProtocolICPAPI
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "client_db.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/UdpOpenDialer.h"
#include "fd.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "md5.h"
#include "multicast.h"
#include "neighbors.h"
#include "refresh.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_key_md5.h"
#include "SwapDir.h"
#include "tools.h"
#include "wordlist.h"

#include <cerrno>

static void icpIncomingConnectionOpened(const Comm::ConnectionPointer &conn, int errNo);

/// \ingroup ServerProtocolICPInternal2
static void icpLogIcp(const Ip::Address &, LogTags, int, const char *, int);

/// \ingroup ServerProtocolICPInternal2
static void icpHandleIcpV2(int, Ip::Address &, char *, int);

/// \ingroup ServerProtocolICPInternal2
static void icpCount(void *, int, size_t, int);

/**
 \ingroup ServerProtocolICPInternal2
 * IcpQueueHead is global so comm_incoming() knows whether or not
 * to call icpUdpSendQueue.
 */
static icpUdpData *IcpQueueHead = NULL;
/// \ingroup ServerProtocolICPInternal2
static icpUdpData *IcpQueueTail = NULL;

/// \ingroup ServerProtocolICPInternal2
Comm::ConnectionPointer icpIncomingConn = NULL;
/// \ingroup ServerProtocolICPInternal2
Comm::ConnectionPointer icpOutgoingConn = NULL;

/* icp_common_t */
_icp_common_t::_icp_common_t() :
    opcode(ICP_INVALID), version(0), length(0), reqnum(0),
    flags(0), pad(0), shostid(0)
{}

_icp_common_t::_icp_common_t(char *buf, unsigned int len) :
    opcode(ICP_INVALID), version(0), reqnum(0), flags(0), pad(0), shostid(0)
{
    if (len < sizeof(_icp_common_t)) {
        /* mark as invalid */
        length = len + 1;
        return;
    }

    memcpy(this, buf, sizeof(icp_common_t));
    /*
     * Convert network order sensitive fields
     */
    length = ntohs(length);
    reqnum = ntohl(reqnum);
    flags = ntohl(flags);
    pad = ntohl(pad);
}

icp_opcode
_icp_common_t::getOpCode() const
{
    if (opcode > (char)ICP_END)
        return ICP_INVALID;

    return (icp_opcode)opcode;
}

/* ICPState */

ICPState::ICPState(icp_common_t &aHeader, HttpRequest *aRequest):
    header(aHeader),
    request(aRequest),
    fd(-1),
    url(NULL)
{
    HTTPMSGLOCK(request);
}

ICPState::~ICPState()
{
    safe_free(url);
    HTTPMSGUNLOCK(request);
}

/* End ICPState */

/* ICP2State */

/// \ingroup ServerProtocolICPInternal2
class ICP2State : public ICPState, public StoreClient
{

public:
    ICP2State(icp_common_t & aHeader, HttpRequest *aRequest):
        ICPState(aHeader, aRequest),rtt(0),src_rtt(0),flags(0) {}

    ~ICP2State();
    void created(StoreEntry * newEntry);

    int rtt;
    int src_rtt;
    uint32_t flags;
};

ICP2State::~ICP2State()
{}

void
ICP2State::created(StoreEntry *newEntry)
{
    StoreEntry *entry = newEntry->isNull () ? NULL : newEntry;
    debugs(12, 5, "icpHandleIcpV2: OPCODE " << icp_opcode_str[header.opcode]);
    icp_opcode codeToSend;

    if (icpCheckUdpHit(entry, request)) {
        codeToSend = ICP_HIT;
    } else {
#if USE_ICMP
        if (Config.onoff.test_reachability && rtt == 0) {
            if ((rtt = netdbHostRtt(request->GetHost())) == 0)
                netdbPingSite(request->GetHost());
        }
#endif /* USE_ICMP */

        if (icpGetCommonOpcode() != ICP_ERR)
            codeToSend = icpGetCommonOpcode();
        else if (Config.onoff.test_reachability && rtt == 0)
            codeToSend = ICP_MISS_NOFETCH;
        else
            codeToSend = ICP_MISS;
    }

    icpCreateAndSend(codeToSend, flags, url, header.reqnum, src_rtt, fd, from);
    delete this;
}

/* End ICP2State */

/// \ingroup ServerProtocolICPInternal2
static void
icpLogIcp(const Ip::Address &caddr, LogTags logcode, int len, const char *url, int delay)
{
    AccessLogEntry::Pointer al = new AccessLogEntry();

    if (LOG_TAG_NONE == logcode)
        return;

    if (LOG_ICP_QUERY == logcode)
        return;

    clientdbUpdate(caddr, logcode, AnyP::PROTO_ICP, len);

    if (!Config.onoff.log_udp)
        return;

    al->icp.opcode = ICP_QUERY;

    al->url = url;

    al->cache.caddr = caddr;

    // XXX: move to use icp.clientReply instead
    al->http.clientReplySz.payloadData = len;

    al->cache.code = logcode;

    al->cache.msec = delay;

    accessLogLog(al, NULL);
}

/// \ingroup ServerProtocolICPInternal2
void
icpUdpSendQueue(int fd, void *unused)
{
    icpUdpData *q;

    while ((q = IcpQueueHead) != NULL) {
        int delay = tvSubUsec(q->queue_time, current_time);
        /* increment delay to prevent looping */
        const int x = icpUdpSend(fd, q->address, (icp_common_t *) q->msg, q->logcode, ++delay);
        IcpQueueHead = q->next;
        xfree(q);

        if (x < 0)
            break;
    }
}

_icp_common_t *
_icp_common_t::createMessage(
    icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad)
{
    char *buf = NULL;
    icp_common_t *headerp = NULL;
    char *urloffset = NULL;
    int buf_len;
    buf_len = sizeof(icp_common_t) + strlen(url) + 1;

    if (opcode == ICP_QUERY)
        buf_len += sizeof(uint32_t);

    buf = (char *) xcalloc(buf_len, 1);

    headerp = (icp_common_t *) (void *) buf;

    headerp->opcode = (char) opcode;

    headerp->version = ICP_VERSION_CURRENT;

    headerp->length = (uint16_t) htons(buf_len);

    headerp->reqnum = htonl(reqnum);

    headerp->flags = htonl(flags);

    headerp->pad = htonl(pad);

    headerp->shostid = 0;

    urloffset = buf + sizeof(icp_common_t);

    if (opcode == ICP_QUERY)
        urloffset += sizeof(uint32_t);

    memcpy(urloffset, url, strlen(url));

    return (icp_common_t *)buf;
}

int
icpUdpSend(int fd,
           const Ip::Address &to,
           icp_common_t * msg,
           LogTags logcode,
           int delay)
{
    icpUdpData *queue;
    int x;
    int len;
    len = (int) ntohs(msg->length);
    debugs(12, 5, "icpUdpSend: FD " << fd << " sending " <<
           icp_opcode_str[msg->opcode] << ", " << len << " bytes to " << to);

    x = comm_udp_sendto(fd, to, msg, len);

    if (x >= 0) {
        /* successfully written */
        icpLogIcp(to, logcode, len, (char *) (msg + 1), delay);
        icpCount(msg, SENT, (size_t) len, delay);
        safe_free(msg);
    } else if (0 == delay) {
        /* send failed, but queue it */
        queue = (icpUdpData *) xcalloc(1, sizeof(icpUdpData));
        queue->address = to;
        queue->msg = msg;
        queue->len = (int) ntohs(msg->length);
        queue->queue_time = current_time;
        queue->logcode = logcode;

        if (IcpQueueHead == NULL) {
            IcpQueueHead = queue;
            IcpQueueTail = queue;
        } else if (IcpQueueTail == IcpQueueHead) {
            IcpQueueTail = queue;
            IcpQueueHead->next = queue;
        } else {
            IcpQueueTail->next = queue;
            IcpQueueTail = queue;
        }

        Comm::SetSelect(fd, COMM_SELECT_WRITE, icpUdpSendQueue, NULL, 0);
        ++statCounter.icp.replies_queued;
    } else {
        /* don't queue it */
        ++statCounter.icp.replies_dropped;
    }

    return x;
}

int
icpCheckUdpHit(StoreEntry * e, HttpRequest * request)
{
    if (e == NULL)
        return 0;

    if (!e->validToSend())
        return 0;

    if (Config.onoff.icp_hit_stale)
        return 1;

    if (refreshCheckICP(e, request))
        return 0;

    return 1;
}

/**
 * This routine selects an ICP opcode for ICP misses.
 *
 \retval ICP_ERR            no opcode selected here
 \retval ICP_MISS_NOFETCH   store is rebuilding, no fetch is possible yet
 */
icp_opcode
icpGetCommonOpcode()
{
    /* if store is rebuilding, return a UDP_MISS_NOFETCH */

    if ((StoreController::store_dirs_rebuilding && opt_reload_hit_only) ||
            hit_only_mode_until > squid_curtime) {
        return ICP_MISS_NOFETCH;
    }

    return ICP_ERR;
}

LogTags
icpLogFromICPCode(icp_opcode opcode)
{
    if (opcode == ICP_ERR)
        return LOG_UDP_INVALID;

    if (opcode == ICP_DENIED)
        return LOG_UDP_DENIED;

    if (opcode == ICP_HIT)
        return LOG_UDP_HIT;

    if (opcode == ICP_MISS)
        return LOG_UDP_MISS;

    if (opcode == ICP_MISS_NOFETCH)
        return LOG_UDP_MISS_NOFETCH;

    fatal("expected ICP opcode\n");

    return LOG_UDP_INVALID;
}

void
icpCreateAndSend(icp_opcode opcode, int flags, char const *url, int reqnum, int pad, int fd, const Ip::Address &from)
{
    icp_common_t *reply = _icp_common_t::createMessage(opcode, flags, url, reqnum, pad);
    icpUdpSend(fd, from, reply, icpLogFromICPCode(opcode), 0);
}

void
icpDenyAccess(Ip::Address &from, char *url, int reqnum, int fd)
{
    debugs(12, 2, "icpDenyAccess: Access Denied for " << from << " by " << AclMatchedName << ".");

    if (clientdbCutoffDenied(from)) {
        /*
         * count this DENIED query in the clientdb, even though
         * we're not sending an ICP reply...
         */
        clientdbUpdate(from, LOG_UDP_DENIED, AnyP::PROTO_ICP, 0);
    } else {
        icpCreateAndSend(ICP_DENIED, 0, url, reqnum, 0, fd, from);
    }
}

bool
icpAccessAllowed(Ip::Address &from, HttpRequest * icp_request)
{
    /* absent any explicit rules, we deny all */
    if (!Config.accessList.icp)
        return false;

    ACLFilledChecklist checklist(Config.accessList.icp, icp_request, NULL);
    checklist.src_addr = from;
    checklist.my_addr.setNoAddr();
    return (checklist.fastCheck() == ACCESS_ALLOWED);
}

char const *
icpGetUrlToSend(char *url)
{
    if (strpbrk(url, w_space))
        return rfc1738_escape(url);
    else
        return url;
}

HttpRequest *
icpGetRequest(char *url, int reqnum, int fd, Ip::Address &from)
{
    if (strpbrk(url, w_space)) {
        url = rfc1738_escape(url);
        icpCreateAndSend(ICP_ERR, 0, rfc1738_escape(url), reqnum, 0, fd, from);
        return NULL;
    }

    HttpRequest *result;

    if ((result = HttpRequest::CreateFromUrl(url)) == NULL)
        icpCreateAndSend(ICP_ERR, 0, url, reqnum, 0, fd, from);

    return result;

}

static void
doV2Query(int fd, Ip::Address &from, char *buf, icp_common_t header)
{
    int rtt = 0;
    int src_rtt = 0;
    uint32_t flags = 0;
    /* We have a valid packet */
    char *url = buf + sizeof(icp_common_t) + sizeof(uint32_t);
    HttpRequest *icp_request = icpGetRequest(url, header.reqnum, fd, from);

    if (!icp_request)
        return;

    HTTPMSGLOCK(icp_request);

    if (!icpAccessAllowed(from, icp_request)) {
        icpDenyAccess(from, url, header.reqnum, fd);
        HTTPMSGUNLOCK(icp_request);
        return;
    }
#if USE_ICMP
    if (header.flags & ICP_FLAG_SRC_RTT) {
        rtt = netdbHostRtt(icp_request->GetHost());
        int hops = netdbHostHops(icp_request->GetHost());
        src_rtt = ((hops & 0xFFFF) << 16) | (rtt & 0xFFFF);

        if (rtt)
            flags |= ICP_FLAG_SRC_RTT;
    }
#endif /* USE_ICMP */

    /* The peer is allowed to use this cache */
    ICP2State *state = new ICP2State(header, icp_request);
    state->fd = fd;
    state->from = from;
    state->url = xstrdup(url);
    state->flags = flags;
    state->rtt = rtt;
    state->src_rtt = src_rtt;

    StoreEntry::getPublic(state, url, Http::METHOD_GET);

    HTTPMSGUNLOCK(icp_request);
}

void
_icp_common_t::handleReply(char *buf, Ip::Address &from)
{
    if (neighbors_do_private_keys && reqnum == 0) {
        debugs(12, DBG_CRITICAL, "icpHandleIcpV2: Neighbor " << from << " returned reqnum = 0");
        debugs(12, DBG_CRITICAL, "icpHandleIcpV2: Disabling use of private keys");
        neighbors_do_private_keys = 0;
    }

    char *url = buf + sizeof(icp_common_t);
    debugs(12, 3, "icpHandleIcpV2: " << icp_opcode_str[opcode] << " from " << from << " for '" << url << "'");

    const cache_key *key = icpGetCacheKey(url, (int) reqnum);
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(key, this, from);
}

static void
icpHandleIcpV2(int fd, Ip::Address &from, char *buf, int len)
{
    if (len <= 0) {
        debugs(12, 3, "icpHandleIcpV2: ICP message is too small");
        return;
    }

    icp_common_t header(buf, len);
    /*
     * Length field should match the number of bytes read
     */

    if (len != header.length) {
        debugs(12, 3, "icpHandleIcpV2: ICP message is too small");
        return;
    }

    switch (header.opcode) {

    case ICP_QUERY:
        /* We have a valid packet */
        doV2Query(fd, from, buf, header);
        break;

    case ICP_HIT:

    case ICP_DECHO:

    case ICP_MISS:

    case ICP_DENIED:

    case ICP_MISS_NOFETCH:
        header.handleReply(buf, from);
        break;

    case ICP_INVALID:

    case ICP_ERR:
        break;

    default:
        debugs(12, DBG_CRITICAL, "icpHandleIcpV2: UNKNOWN OPCODE: " << header.opcode << " from " << from);

        break;
    }
}

#ifdef ICP_PKT_DUMP
static void
icpPktDump(icp_common_t * pkt)
{
    Ip::Address a;

    debugs(12, 9, "opcode:     " << std::setw(3) << pkt->opcode  << " " << icp_opcode_str[pkt->opcode]);
    debugs(12, 9, "version: "<< std::left << std::setw(8) << pkt->version);
    debugs(12, 9, "length:  "<< std::left << std::setw(8) << ntohs(pkt->length));
    debugs(12, 9, "reqnum:  "<< std::left << std::setw(8) << ntohl(pkt->reqnum));
    debugs(12, 9, "flags:   "<< std::left << std::hex << std::setw(8) << ntohl(pkt->flags));
    a = (struct in_addr)pkt->shostid;
    debugs(12, 9, "shostid: " << a );
    debugs(12, 9, "payload: " << (char *) pkt + sizeof(icp_common_t));
}

#endif

void
icpHandleUdp(int sock, void *data)
{
    int *N = &incoming_sockets_accepted;

    Ip::Address from;
    LOCAL_ARRAY(char, buf, SQUID_UDP_SO_RCVBUF);
    int len;
    int icp_version;
    int max = INCOMING_UDP_MAX;
    Comm::SetSelect(sock, COMM_SELECT_READ, icpHandleUdp, NULL, 0);

    while (max) {
        --max;
        len = comm_udp_recvfrom(sock,
                                buf,
                                SQUID_UDP_SO_RCVBUF - 1,
                                0,
                                from);

        if (len == 0)
            break;

        if (len < 0) {
            if (ignoreErrno(errno))
                break;

#if _SQUID_LINUX_
            /* Some Linux systems seem to set the FD for reading and then
             * return ECONNREFUSED when sendto() fails and generates an ICMP
             * port unreachable message. */
            /* or maybe an EHOSTUNREACH "No route to host" message */
            if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif

                debugs(50, DBG_IMPORTANT, "icpHandleUdp: FD " << sock << " recvfrom: " << xstrerror());

            break;
        }

        ++(*N);
        icpCount(buf, RECV, (size_t) len, 0);
        buf[len] = '\0';
        debugs(12, 4, "icpHandleUdp: FD " << sock << ": received " <<
               (unsigned long int)len << " bytes from " << from);

#ifdef ICP_PACKET_DUMP

        icpPktDump(buf);
#endif

        if ((size_t) len < sizeof(icp_common_t)) {
            debugs(12, 4, "icpHandleUdp: Ignoring too-small UDP packet");
            break;
        }

        icp_version = (int) buf[1]; /* cheat! */

        if (icpOutgoingConn->local == from)
            // ignore ICP packets which loop back (multicast usually)
            debugs(12, 4, "icpHandleUdp: Ignoring UDP packet sent by myself");
        else if (icp_version == ICP_VERSION_2)
            icpHandleIcpV2(sock, from, buf, len);
        else if (icp_version == ICP_VERSION_3)
            icpHandleIcpV3(sock, from, buf, len);
        else
            debugs(12, DBG_IMPORTANT, "WARNING: Unused ICP version " << icp_version <<
                   " received from " << from);
    }
}

void
icpOpenPorts(void)
{
    uint16_t port;

    if ((port = Config.Port.icp) <= 0)
        return;

    icpIncomingConn = new Comm::Connection;
    icpIncomingConn->local = Config.Addrs.udp_incoming;
    icpIncomingConn->local.port(port);

    if (!Ip::EnableIpv6 && !icpIncomingConn->local.setIPv4()) {
        debugs(12, DBG_CRITICAL, "ERROR: IPv6 is disabled. " << icpIncomingConn->local << " is not an IPv4 address.");
        fatal("ICP port cannot be opened.");
    }
    /* split-stack for now requires default IPv4-only ICP */
    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && icpIncomingConn->local.isAnyAddr()) {
        icpIncomingConn->local.setIPv4();
    }

    AsyncCall::Pointer call = asyncCall(12, 2,
                                        "icpIncomingConnectionOpened",
                                        Comm::UdpOpenDialer(&icpIncomingConnectionOpened));

    Ipc::StartListening(SOCK_DGRAM,
                        IPPROTO_UDP,
                        icpIncomingConn,
                        Ipc::fdnInIcpSocket, call);

    if ( !Config.Addrs.udp_outgoing.isNoAddr() ) {
        icpOutgoingConn = new Comm::Connection;
        icpOutgoingConn->local = Config.Addrs.udp_outgoing;
        icpOutgoingConn->local.port(port);

        if (!Ip::EnableIpv6 && !icpOutgoingConn->local.setIPv4()) {
            debugs(49, DBG_CRITICAL, "ERROR: IPv6 is disabled. " << icpOutgoingConn->local << " is not an IPv4 address.");
            fatal("ICP port cannot be opened.");
        }
        /* split-stack for now requires default IPv4-only ICP */
        if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && icpOutgoingConn->local.isAnyAddr()) {
            icpOutgoingConn->local.setIPv4();
        }

        enter_suid();
        comm_open_listener(SOCK_DGRAM, IPPROTO_UDP, icpOutgoingConn, "Outgoing ICP Port");
        leave_suid();

        if (!Comm::IsConnOpen(icpOutgoingConn))
            fatal("Cannot open Outgoing ICP Port");

        debugs(12, DBG_CRITICAL, "Sending ICP messages from " << icpOutgoingConn->local);

        Comm::SetSelect(icpOutgoingConn->fd, COMM_SELECT_READ, icpHandleUdp, NULL, 0);
        fd_note(icpOutgoingConn->fd, "Outgoing ICP socket");
    }
}

static void
icpIncomingConnectionOpened(const Comm::ConnectionPointer &conn, int errNo)
{
    if (!Comm::IsConnOpen(conn))
        fatal("Cannot open ICP Port");

    Comm::SetSelect(conn->fd, COMM_SELECT_READ, icpHandleUdp, NULL, 0);

    for (const wordlist *s = Config.mcast_group_list; s; s = s->next)
        ipcache_nbgethostbyname(s->key, mcastJoinGroups, NULL); // XXX: pass the conn for mcastJoinGroups usage.

    debugs(12, DBG_IMPORTANT, "Accepting ICP messages on " << conn->local);

    fd_note(conn->fd, "Incoming ICP port");

    if (Config.Addrs.udp_outgoing.isNoAddr()) {
        icpOutgoingConn = conn;
        debugs(12, DBG_IMPORTANT, "Sending ICP messages from " << icpOutgoingConn->local);
    }
}

/**
 * icpConnectionShutdown only closes the 'in' socket if it is
 * different than the 'out' socket.
 */
void
icpConnectionShutdown(void)
{
    if (!Comm::IsConnOpen(icpIncomingConn))
        return;

    debugs(12, DBG_IMPORTANT, "Stop receiving ICP on " << icpIncomingConn->local);

    /** Release the 'in' socket for lazy closure.
     * in and out sockets may be sharing one same FD.
     * This prevents this function from executing repeatedly.
     */
    icpIncomingConn = NULL;

    /**
     * Normally we only write to the outgoing ICP socket, but
     * we also have a read handler there to catch messages sent
     * to that specific interface.  During shutdown, we must
     * disable reading on the outgoing socket.
     */
    assert(Comm::IsConnOpen(icpOutgoingConn));

    Comm::SetSelect(icpOutgoingConn->fd, COMM_SELECT_READ, NULL, NULL, 0);
}

void
icpClosePorts(void)
{
    icpConnectionShutdown();

    if (icpOutgoingConn != NULL) {
        debugs(12, DBG_IMPORTANT, "Stop sending ICP from " << icpOutgoingConn->local);
        icpOutgoingConn = NULL;
    }
}

static void
icpCount(void *buf, int which, size_t len, int delay)
{
    icp_common_t *icp = (icp_common_t *) buf;

    if (len < sizeof(*icp))
        return;

    if (SENT == which) {
        ++statCounter.icp.pkts_sent;
        kb_incr(&statCounter.icp.kbytes_sent, len);

        if (ICP_QUERY == icp->opcode) {
            ++statCounter.icp.queries_sent;
            kb_incr(&statCounter.icp.q_kbytes_sent, len);
        } else {
            ++statCounter.icp.replies_sent;
            kb_incr(&statCounter.icp.r_kbytes_sent, len);
            /* this is the sent-reply service time */
            statCounter.icp.replySvcTime.count(delay);
        }

        if (ICP_HIT == icp->opcode)
            ++statCounter.icp.hits_sent;
    } else if (RECV == which) {
        ++statCounter.icp.pkts_recv;
        kb_incr(&statCounter.icp.kbytes_recv, len);

        if (ICP_QUERY == icp->opcode) {
            ++statCounter.icp.queries_recv;
            kb_incr(&statCounter.icp.q_kbytes_recv, len);
        } else {
            ++statCounter.icp.replies_recv;
            kb_incr(&statCounter.icp.r_kbytes_recv, len);
            /* statCounter.icp.querySvcTime set in clientUpdateCounters */
        }

        if (ICP_HIT == icp->opcode)
            ++statCounter.icp.hits_recv;
    }
}

#define N_QUERIED_KEYS 8192
#define N_QUERIED_KEYS_MASK 8191
static cache_key queried_keys[N_QUERIED_KEYS][SQUID_MD5_DIGEST_LENGTH];

int
icpSetCacheKey(const cache_key * key)
{
    static int reqnum = 0;

    if (++reqnum < 0)
        reqnum = 1;

    storeKeyCopy(queried_keys[reqnum & N_QUERIED_KEYS_MASK], key);

    return reqnum;
}

const cache_key *
icpGetCacheKey(const char *url, int reqnum)
{
    if (neighbors_do_private_keys && reqnum)
        return queried_keys[reqnum & N_QUERIED_KEYS_MASK];

    return storeKeyPublic(url, Http::METHOD_GET);
}

