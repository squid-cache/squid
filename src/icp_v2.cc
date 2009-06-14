/*
 * DEBUG: section 12    Internet Cache Protocol (ICP)
 * AUTHOR: Duane Wessels
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

/**
 \defgroup ServerProtocolICPInternal2 ICPv2 Internals
 \ingroup ServerProtocolICPAPI
 */

#include "squid.h"
#include "Store.h"
#include "comm.h"
#include "ICP.h"
#include "HttpRequest.h"
#include "acl/FilledChecklist.h"
#include "acl/Acl.h"
#include "AccessLogEntry.h"
#include "wordlist.h"
#include "SquidTime.h"
#include "SwapDir.h"
#include "icmp/net_db.h"
#include "ip/IpAddress.h"

/// \ingroup ServerProtocolICPInternal2
static void icpLogIcp(const IpAddress &, log_type, int, const char *, int);

/// \ingroup ServerProtocolICPInternal2
static void icpHandleIcpV2(int, IpAddress &, char *, int);

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
IpAddress theOutICPAddr;

/* icp_common_t */
_icp_common_t::_icp_common_t() : opcode(ICP_INVALID), version(0), length(0), reqnum(0), flags(0), pad(0), shostid(0)
{}

_icp_common_t::_icp_common_t(char *buf, unsigned int len)
{
    if (len < sizeof(_icp_common_t)) {
        /* mark as invalid */
        length = len + 1;
        return;
    }

    xmemcpy(this, buf, sizeof(icp_common_t));
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
        request(HTTPMSGLOCK(aRequest)),
        fd(-1),
        url(NULL)
{}

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
    u_int32_t flags;
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
icpLogIcp(const IpAddress &caddr, log_type logcode, int len, const char *url, int delay)
{
    AccessLogEntry al;

    if (LOG_TAG_NONE == logcode)
        return;

    if (LOG_ICP_QUERY == logcode)
        return;

    clientdbUpdate(caddr, logcode, PROTO_ICP, len);

    if (!Config.onoff.log_udp)
        return;

    al.icp.opcode = ICP_QUERY;

    al.url = url;

    al.cache.caddr = caddr;

    al.cache.replySize = len;

    al.cache.code = logcode;

    al.cache.msec = delay;

    accessLogLog(&al, NULL);
}

/// \ingroup ServerProtocolICPInternal2
void
icpUdpSendQueue(int fd, void *unused)
{
    icpUdpData *q;
    int x;
    int delay;

    while ((q = IcpQueueHead) != NULL) {
        delay = tvSubUsec(q->queue_time, current_time);
        /* increment delay to prevent looping */
        x = icpUdpSend(fd, q->address, (icp_common_t *) q->msg, q->logcode, ++delay);
        IcpQueueHead = q->next;
        safe_free(q);

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
        buf_len += sizeof(u_int32_t);

    buf = (char *) xcalloc(buf_len, 1);

    headerp = (icp_common_t *) (void *) buf;

    headerp->opcode = (char) opcode;

    headerp->version = ICP_VERSION_CURRENT;

    headerp->length = (u_int16_t) htons(buf_len);

    headerp->reqnum = htonl(reqnum);

    headerp->flags = htonl(flags);

    headerp->pad = htonl(pad);

    theOutICPAddr.GetInAddr( *((struct in_addr*)&headerp->shostid) );

    urloffset = buf + sizeof(icp_common_t);

    if (opcode == ICP_QUERY)
        urloffset += sizeof(u_int32_t);

    xmemcpy(urloffset, url, strlen(url));

    return (icp_common_t *)buf;
}

int
icpUdpSend(int fd,
           const IpAddress &to,
           icp_common_t * msg,
           log_type logcode,
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

        commSetSelect(fd, COMM_SELECT_WRITE, icpUdpSendQueue, NULL, 0);
        statCounter.icp.replies_queued++;
    } else {
        /* don't queue it */
        statCounter.icp.replies_dropped++;
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

log_type
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
icpCreateAndSend(icp_opcode opcode, int flags, char const *url, int reqnum, int pad, int fd, const IpAddress &from)
{
    icp_common_t *reply = _icp_common_t::createMessage(opcode, flags, url, reqnum, pad);
    icpUdpSend(fd, from, reply, icpLogFromICPCode(opcode), 0);
}

void
icpDenyAccess(IpAddress &from, char *url, int reqnum, int fd)
{
    debugs(12, 2, "icpDenyAccess: Access Denied for " << from << " by " << AclMatchedName << ".");

    if (clientdbCutoffDenied(from)) {
        /*
         * count this DENIED query in the clientdb, even though
         * we're not sending an ICP reply...
         */
        clientdbUpdate(from, LOG_UDP_DENIED, PROTO_ICP, 0);
    } else {
        icpCreateAndSend(ICP_DENIED, 0, url, reqnum, 0, fd, from);
    }
}

int
icpAccessAllowed(IpAddress &from, HttpRequest * icp_request)
{
    /* absent an explicit allow, we deny all */
    if (!Config.accessList.icp)
        return 0;

    ACLFilledChecklist checklist(Config.accessList.icp, icp_request, NULL);
    checklist.src_addr = from;
    checklist.my_addr.SetNoAddr();
    int result = checklist.fastCheck();
    return result;
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
icpGetRequest(char *url, int reqnum, int fd, IpAddress &from)
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
doV2Query(int fd, IpAddress &from, char *buf, icp_common_t header)
{
    int rtt = 0;
    int src_rtt = 0;
    u_int32_t flags = 0;
    /* We have a valid packet */
    char *url = buf + sizeof(icp_common_t) + sizeof(u_int32_t);
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
    ICP2State *state = new ICP2State (header, icp_request);

    state->fd = fd;

    state->from = from;

    state->url = xstrdup (url);

    state->flags = flags;

    state->rtt = rtt;

    state->src_rtt = src_rtt;

    StoreEntry::getPublic (state, url, METHOD_GET);

    HTTPMSGUNLOCK(icp_request);
}

void
_icp_common_t::handleReply(char *buf, IpAddress &from)
{
    if (neighbors_do_private_keys && reqnum == 0) {
        debugs(12, 0, "icpHandleIcpV2: Neighbor " << from << " returned reqnum = 0");
        debugs(12, 0, "icpHandleIcpV2: Disabling use of private keys");
        neighbors_do_private_keys = 0;
    }

    char *url = buf + sizeof(icp_common_t);
    debugs(12, 3, "icpHandleIcpV2: " << icp_opcode_str[opcode] << " from " << from << " for '" << url << "'");

    const cache_key *key = icpGetCacheKey(url, (int) reqnum);
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(key, this, from);
}

static void
icpHandleIcpV2(int fd, IpAddress &from, char *buf, int len)
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
        debugs(12, 0, "icpHandleIcpV2: UNKNOWN OPCODE: " << header.opcode << " from " << from);

        break;
    }
}

#ifdef ICP_PKT_DUMP
static void
icpPktDump(icp_common_t * pkt)
{

    IpAddress a;

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

    IpAddress from;
    LOCAL_ARRAY(char, buf, SQUID_UDP_SO_RCVBUF);
    int len;
    int icp_version;
    int max = INCOMING_ICP_MAX;
    commSetSelect(sock, COMM_SELECT_READ, icpHandleUdp, NULL, 0);

    while (max--) {
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

#ifdef _SQUID_LINUX_
            /* Some Linux systems seem to set the FD for reading and then
             * return ECONNREFUSED when sendto() fails and generates an ICMP
             * port unreachable message. */
            /* or maybe an EHOSTUNREACH "No route to host" message */
            if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif

                debugs(50, 1, "icpHandleUdp: FD " << sock << " recvfrom: " << xstrerror());

            break;
        }

        (*N)++;
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

        icp_version = (int) buf[1];	/* cheat! */

        if (icp_version == ICP_VERSION_2)
            icpHandleIcpV2(sock, from, buf, len);
        else if (icp_version == ICP_VERSION_3)
            icpHandleIcpV3(sock, from, buf, len);
        else
            debugs(12, 1, "WARNING: Unused ICP version " << icp_version <<
                   " received from " << from);
    }
}

void
icpConnectionsOpen(void)
{
    u_int16_t port;

    IpAddress addr;

    struct addrinfo *xai = NULL;
    int x;
    wordlist *s;

    if ((port = Config.Port.icp) <= 0)
        return;

    enter_suid();

    addr = Config.Addrs.udp_incoming;
    addr.SetPort(port);
    theInIcpConnection = comm_open_listener(SOCK_DGRAM,
                                            IPPROTO_UDP,
                                            addr,
                                            COMM_NONBLOCKING,
                                            "ICP Socket");
    leave_suid();

    if (theInIcpConnection < 0)
        fatal("Cannot open ICP Port");

    commSetSelect(theInIcpConnection,
                  COMM_SELECT_READ,
                  icpHandleUdp,
                  NULL,
                  0);

    for (s = Config.mcast_group_list; s; s = s->next)
        ipcache_nbgethostbyname(s->key, mcastJoinGroups, NULL);

    debugs(12, 1, "Accepting ICP messages at " << addr << ", FD " << theInIcpConnection << ".");

    addr.SetEmpty(); // clear for next use.
    addr = Config.Addrs.udp_outgoing;
    if ( !addr.IsNoAddr() ) {
        enter_suid();
        addr.SetPort(port);
        theOutIcpConnection = comm_open_listener(SOCK_DGRAM,
                              IPPROTO_UDP,
                              addr,
                              COMM_NONBLOCKING,
                              "ICP Port");
        leave_suid();

        if (theOutIcpConnection < 0)
            fatal("Cannot open Outgoing ICP Port");

        commSetSelect(theOutIcpConnection,
                      COMM_SELECT_READ,
                      icpHandleUdp,
                      NULL,
                      0);

        debugs(12, 1, "Outgoing ICP messages on port " << addr.GetPort() << ", FD " << theOutIcpConnection << ".");

        fd_note(theOutIcpConnection, "Outgoing ICP socket");

        fd_note(theInIcpConnection, "Incoming ICP socket");
    } else {
        theOutIcpConnection = theInIcpConnection;
    }

    theOutICPAddr.SetEmpty();

    theOutICPAddr.InitAddrInfo(xai);

    x = getsockname(theOutIcpConnection, xai->ai_addr, &xai->ai_addrlen);

    if (x < 0)
        debugs(50, 1, "theOutIcpConnection FD " << theOutIcpConnection << ": getsockname: " << xstrerror());
    else
        theOutICPAddr = *xai;

    theOutICPAddr.FreeAddrInfo(xai);
}

/**
 * icpConnectionShutdown only closes the 'in' socket if it is
 * different than the 'out' socket.
 */
void
icpConnectionShutdown(void)
{
    if (theInIcpConnection < 0)
        return;

    if (theInIcpConnection != theOutIcpConnection) {
        debugs(12, 1, "FD " << theInIcpConnection << " Closing ICP connection");
        comm_close(theInIcpConnection);
    }

    /**
     * Here we set 'theInIcpConnection' to -1 even though the ICP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */
    theInIcpConnection = -1;

    /**
     * Normally we only write to the outgoing ICP socket, but
     * we also have a read handler there to catch messages sent
     * to that specific interface.  During shutdown, we must
     * disable reading on the outgoing socket.
     */
    assert(theOutIcpConnection > -1);

    commSetSelect(theOutIcpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}

void
icpConnectionClose(void)
{
    icpConnectionShutdown();

    if (theOutIcpConnection > -1) {
        debugs(12, 1, "FD " << theOutIcpConnection << " Closing ICP connection");
        comm_close(theOutIcpConnection);
        theOutIcpConnection = -1;
    }
}

static void
icpCount(void *buf, int which, size_t len, int delay)
{
    icp_common_t *icp = (icp_common_t *) buf;

    if (len < sizeof(*icp))
        return;

    if (SENT == which) {
        statCounter.icp.pkts_sent++;
        kb_incr(&statCounter.icp.kbytes_sent, len);

        if (ICP_QUERY == icp->opcode) {
            statCounter.icp.queries_sent++;
            kb_incr(&statCounter.icp.q_kbytes_sent, len);
        } else {
            statCounter.icp.replies_sent++;
            kb_incr(&statCounter.icp.r_kbytes_sent, len);
            /* this is the sent-reply service time */
            statHistCount(&statCounter.icp.reply_svc_time, delay);
        }

        if (ICP_HIT == icp->opcode)
            statCounter.icp.hits_sent++;
    } else if (RECV == which) {
        statCounter.icp.pkts_recv++;
        kb_incr(&statCounter.icp.kbytes_recv, len);

        if (ICP_QUERY == icp->opcode) {
            statCounter.icp.queries_recv++;
            kb_incr(&statCounter.icp.q_kbytes_recv, len);
        } else {
            statCounter.icp.replies_recv++;
            kb_incr(&statCounter.icp.r_kbytes_recv, len);
            /* statCounter.icp.query_svc_time set in clientUpdateCounters */
        }

        if (ICP_HIT == icp->opcode)
            statCounter.icp.hits_recv++;
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

    return storeKeyPublic(url, METHOD_GET);
}
