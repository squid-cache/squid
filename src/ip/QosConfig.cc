/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/Gadgets.h"
#include "cache_cf.h"
#include "comm/Connection.h"
#include "compat/cmsg.h"
#include "ConfigParser.h"
#include "fde.h"
#include "globals.h"
#include "hier_code.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "Parsing.h"

#include <cerrno>

CBDATA_CLASS_INIT(acl_tos);

acl_tos::~acl_tos()
{
    aclDestroyAclList(&aclList);
    delete next;
}

CBDATA_CLASS_INIT(acl_nfmark);

acl_nfmark::~acl_nfmark()
{
    aclDestroyAclList(&aclList);
    delete next;
}

void
Ip::Qos::getTosFromServer(const Comm::ConnectionPointer &server, fde *clientFde)
{
#if USE_QOS_TOS && _SQUID_LINUX_
    /* Bug 2537: This part of ZPH only applies to patched Linux kernels. */
    tos_t tos = 1;
    int tos_len = sizeof(tos);
    clientFde->tosFromServer = 0;
    if (setsockopt(server->fd,SOL_IP,IP_RECVTOS,&tos,tos_len)==0) {
        unsigned char buf[512];
        int len = 512;
        if (getsockopt(server->fd,SOL_IP,IP_PKTOPTIONS,buf,(socklen_t*)&len) == 0) {
            /* Parse the PKTOPTIONS structure to locate the TOS data message
             * prepared in the kernel by the ZPH incoming TCP TOS preserving
             * patch.
             */
            unsigned char * pbuf = buf;
            while (pbuf-buf < len) {
                struct cmsghdr *o = (struct cmsghdr*)pbuf;
                if (o->cmsg_len<=0)
                    break;

                if (o->cmsg_level == SOL_IP && o->cmsg_type == IP_TOS) {
                    int *tmp = (int*)SQUID_CMSG_DATA(o);
                    clientFde->tosFromServer = (tos_t)*tmp;
                    break;
                }
                pbuf += CMSG_LEN(o->cmsg_len);
            }
        } else {
            int xerrno = errno;
            debugs(33, DBG_IMPORTANT, "QOS: error in getsockopt(IP_PKTOPTIONS) on " << server << " " << xstrerr(xerrno));
        }
    } else {
        int xerrno = errno;
        debugs(33, DBG_IMPORTANT, "QOS: error in setsockopt(IP_RECVTOS) on " << server << " " << xstrerr(xerrno));
    }
#endif
}

nfmark_t
Ip::Qos::getNfmarkFromConnection(const Comm::ConnectionPointer &conn, const Ip::Qos::ConnectionDirection connDir)
{
    nfmark_t mark = 0;
#if USE_LIBNETFILTERCONNTRACK
    /* Allocate a new conntrack */
    if (struct nf_conntrack *ct = nfct_new()) {
        /* Prepare data needed to find the connection in the conntrack table.
         * We need the local and remote IP address, and the local and remote
         * port numbers.
         */
        const auto src = (connDir == Ip::Qos::dirAccepted) ? conn->remote : conn->local;
        const auto dst = (connDir == Ip::Qos::dirAccepted) ? conn->local : conn->remote;

        if (Ip::EnableIpv6 && src.isIPv6()) {
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
            struct in6_addr conn_fde_dst_ip6;
            dst.getInAddr(conn_fde_dst_ip6);
            nfct_set_attr(ct, ATTR_ORIG_IPV6_DST, conn_fde_dst_ip6.s6_addr);
            struct in6_addr conn_fde_src_ip6;
            src.getInAddr(conn_fde_src_ip6);
            nfct_set_attr(ct, ATTR_ORIG_IPV6_SRC, conn_fde_src_ip6.s6_addr);
        } else {
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
            struct in_addr conn_fde_dst_ip;
            dst.getInAddr(conn_fde_dst_ip);
            nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, conn_fde_dst_ip.s_addr);
            struct in_addr conn_fde_src_ip;
            src.getInAddr(conn_fde_src_ip);
            nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, conn_fde_src_ip.s_addr);
        }

        nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
        nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(dst.port()));
        nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(src.port()));

        /* Open a handle to the conntrack */
        if (struct nfct_handle *h = nfct_open(CONNTRACK, 0)) {
            /* Register the callback. The callback function will record the mark value. */
            nfct_callback_register(h, NFCT_T_ALL, getNfmarkCallback, static_cast<void *>(&mark));
            /* Query the conntrack table using the data previously set */
            int x = nfct_query(h, NFCT_Q_GET, ct);
            if (x == -1) {
                const int xerrno = errno;
                debugs(17, 2, "QOS: Failed to retrieve connection mark: (" << x << ") " << xstrerr(xerrno)
                       << " (Destination " << dst << ", source " << src << ")" );
            }
            nfct_close(h);
        } else {
            debugs(17, 2, "QOS: Failed to open conntrack handle for netfilter mark retrieval.");
        }
        nfct_destroy(ct);
    } else {
        debugs(17, 2, "QOS: Failed to allocate new conntrack for netfilter mark retrieval.");
    }
#endif
    return mark;
}

#if USE_LIBNETFILTERCONNTRACK
int
Ip::Qos::getNfmarkCallback(enum nf_conntrack_msg_type,
                           struct nf_conntrack *ct,
                           void *connmark)
{
    auto *mark = static_cast<nfmark_t *>(connmark);
    *mark = nfct_get_attr_u32(ct, ATTR_MARK);
    debugs(17, 3, asHex(*mark));
    return NFCT_CB_CONTINUE;
}
#endif

int
Ip::Qos::doTosLocalMiss(const Comm::ConnectionPointer &conn, const hier_code hierCode)
{
    tos_t tos = 0;
    if (Ip::Qos::TheConfig.tosSiblingHit && hierCode==SIBLING_HIT) {
        tos = Ip::Qos::TheConfig.tosSiblingHit;
        debugs(33, 2, "QOS: Sibling Peer hit with hier code=" << hierCode << ", TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.tosParentHit && hierCode==PARENT_HIT) {
        tos = Ip::Qos::TheConfig.tosParentHit;
        debugs(33, 2, "QOS: Parent Peer hit with hier code=" << hierCode << ", TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.preserveMissTos) {
        tos = fd_table[conn->fd].tosFromServer & Ip::Qos::TheConfig.preserveMissTosMask;
        tos = (tos & ~Ip::Qos::TheConfig.tosMissMask) | (Ip::Qos::TheConfig.tosMiss & Ip::Qos::TheConfig.tosMissMask);
        debugs(33, 2, "QOS: Preserving TOS on miss, TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.tosMiss) {
        tos = Ip::Qos::TheConfig.tosMiss & Ip::Qos::TheConfig.tosMissMask;
        debugs(33, 2, "QOS: Cache miss, setting TOS=" << int(tos));
    }
    return setSockTos(conn, tos);
}

int
Ip::Qos::doNfmarkLocalMiss(const Comm::ConnectionPointer &conn, const hier_code hierCode)
{
    nfmark_t mark = 0;
    if (Ip::Qos::TheConfig.markSiblingHit && hierCode==SIBLING_HIT) {
        mark = Ip::Qos::TheConfig.markSiblingHit;
        debugs(33, 2, "QOS: Sibling Peer hit with hier code=" << hierCode << ", Mark=" << mark);
    } else if (Ip::Qos::TheConfig.markParentHit && hierCode==PARENT_HIT) {
        mark = Ip::Qos::TheConfig.markParentHit;
        debugs(33, 2, "QOS: Parent Peer hit with hier code=" << hierCode << ", Mark=" << mark);
    } else if (Ip::Qos::TheConfig.preserveMissMark) {
        mark = fd_table[conn->fd].nfmarkFromServer & Ip::Qos::TheConfig.preserveMissMarkMask;
        mark = (mark & ~Ip::Qos::TheConfig.markMissMask) | (Ip::Qos::TheConfig.markMiss & Ip::Qos::TheConfig.markMissMask);
        debugs(33, 2, "QOS: Preserving mark on miss, Mark=" << mark);
    } else if (Ip::Qos::TheConfig.markMiss) {
        mark = Ip::Qos::TheConfig.markMiss & Ip::Qos::TheConfig.markMissMask;
        debugs(33, 2, "QOS: Cache miss, setting Mark=" << mark);
    }
    return setSockNfmark(conn, mark);
}

int
Ip::Qos::doTosLocalHit(const Comm::ConnectionPointer &conn)
{
    debugs(33, 2, "QOS: Setting TOS for local hit, TOS=" << int(Ip::Qos::TheConfig.tosLocalHit));
    return setSockTos(conn, Ip::Qos::TheConfig.tosLocalHit);
}

int
Ip::Qos::doNfmarkLocalHit(const Comm::ConnectionPointer &conn)
{
    debugs(33, 2, "QOS: Setting netfilter mark for local hit, mark=" << Ip::Qos::TheConfig.markLocalHit);
    return setSockNfmark(conn, Ip::Qos::TheConfig.markLocalHit);
}

/* Qos::Config class */

Ip::Qos::Config Ip::Qos::TheConfig;

Ip::Qos::Config::Config() : tosLocalHit(0), tosSiblingHit(0), tosParentHit(0),
    tosMiss(0), tosMissMask(0), preserveMissTos(false),
    preserveMissTosMask(0xFF), markLocalHit(0), markSiblingHit(0),
    markParentHit(0), markMiss(0), markMissMask(0),
    preserveMissMark(false), preserveMissMarkMask(0xFFFFFFFF),
    tosToServer(NULL), tosToClient(NULL), nfmarkToServer(NULL),
    nfmarkToClient(NULL)
{
}

void
Ip::Qos::Config::parseConfigLine()
{
    /* parse options ... */
    char *token;
    /* These are set as appropriate and then used to check whether the initial loop has been done */
    bool mark = false;
    bool tos = false;
    /* Assume preserve is true. We don't set at initialisation as this affects isHitTosActive().
       We have to do this now, as we may never match the 'tos' parameter below */
#if !USE_QOS_TOS
    debugs(3, DBG_CRITICAL, "ERROR: Invalid option 'qos_flows'. QOS features not enabled in this build");
    self_destruct();
#endif

    while ( (token = ConfigParser::NextToken()) ) {

        // Work out TOS or mark. Default to TOS for backwards compatibility
        if (!(mark || tos)) {
            if (strncmp(token, "mark",4) == 0) {
#if SO_MARK && USE_LIBCAP
                mark = true;
                // Assume preserve is true. We don't set at initialisation as this affects isHitNfmarkActive()
#if USE_LIBNETFILTERCONNTRACK
                preserveMissMark = true;
# else // USE_LIBNETFILTERCONNTRACK
                preserveMissMark = false;
                debugs(3, DBG_IMPORTANT, "WARNING: Squid not compiled with Netfilter conntrack library. "
                       << "Netfilter mark preservation not available.");
#endif // USE_LIBNETFILTERCONNTRACK
#elif SO_MARK // SO_MARK && USE_LIBCAP
                debugs(3, DBG_CRITICAL, "ERROR: Invalid parameter 'mark' in qos_flows option. "
                       << "Linux Netfilter marking not available without LIBCAP support.");
                self_destruct();
#else // SO_MARK && USE_LIBCAP
                debugs(3, DBG_CRITICAL, "ERROR: Invalid parameter 'mark' in qos_flows option. "
                       << "Linux Netfilter marking not available on this platform.");
                self_destruct();
#endif // SO_MARK && USE_LIBCAP
            } else if (strncmp(token, "tos",3) == 0) {
                preserveMissTos = true;
                tos = true;
            } else {
                preserveMissTos = true;
                tos = true;
            }
        }

        if (strncmp(token, "local-hit=",10) == 0) {

            if (mark) {
                if (!xstrtoui(&token[10], NULL, &markLocalHit, 0, std::numeric_limits<nfmark_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad mark local-hit value " << &token[10]);
                    self_destruct();
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[10], NULL, &v, 0, std::numeric_limits<tos_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad TOS local-hit value " << &token[10]);
                    self_destruct();
                }
                tosLocalHit = (tos_t)v;
            }

        } else if (strncmp(token, "sibling-hit=",12) == 0) {

            if (mark) {
                if (!xstrtoui(&token[12], NULL, &markSiblingHit, 0, std::numeric_limits<nfmark_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad mark sibling-hit value " << &token[12]);
                    self_destruct();
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[12], NULL, &v, 0, std::numeric_limits<tos_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad TOS sibling-hit value " << &token[12]);
                    self_destruct();
                }
                tosSiblingHit = (tos_t)v;
            }

        } else if (strncmp(token, "parent-hit=",11) == 0) {

            if (mark) {
                if (!xstrtoui(&token[11], NULL, &markParentHit, 0, std::numeric_limits<nfmark_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad mark parent-hit value " << &token[11]);
                    self_destruct();
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[11], NULL, &v, 0, std::numeric_limits<tos_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad TOS parent-hit value " << &token[11]);
                    self_destruct();
                }
                tosParentHit = (tos_t)v;
            }

        } else if (strncmp(token, "miss=",5) == 0) {

            char *end;
            if (mark) {
                if (!xstrtoui(&token[5], &end, &markMiss, 0, std::numeric_limits<nfmark_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad mark miss value " << &token[5]);
                    self_destruct();
                }
                if (*end == '/') {
                    if (!xstrtoui(end + 1, NULL, &markMissMask, 0, std::numeric_limits<nfmark_t>::max())) {
                        debugs(3, DBG_CRITICAL, "ERROR: Bad mark miss mask value " << (end + 1) << ". Using 0xFFFFFFFF instead.");
                        markMissMask = 0xFFFFFFFF;
                    }
                } else {
                    markMissMask = 0xFFFFFFFF;
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[5], &end, &v, 0, std::numeric_limits<tos_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad TOS miss value " << &token[5]);
                    self_destruct();
                }
                tosMiss = (tos_t)v;
                if (*end == '/') {
                    if (!xstrtoui(end + 1, NULL, &v, 0, std::numeric_limits<tos_t>::max())) {
                        debugs(3, DBG_CRITICAL, "ERROR: Bad TOS miss mask value " << (end + 1) << ". Using 0xFF instead.");
                        tosMissMask = 0xFF;
                    } else
                        tosMissMask = (tos_t)v;
                } else {
                    tosMissMask = 0xFF;
                }
            }

        } else if (strcmp(token, "disable-preserve-miss") == 0) {

            if (preserveMissTosMask!=0xFFU || preserveMissMarkMask!=0xFFFFFFFFU) {
                debugs(3, DBG_CRITICAL, "ERROR: miss-mask feature cannot be set with disable-preserve-miss");
                self_destruct();
            }
            if (mark) {
                preserveMissMark = false;
                preserveMissMarkMask = 0;
            } else {
                preserveMissTos = false;
                preserveMissTosMask = 0;
            }

        } else if (strncmp(token, "miss-mask=",10) == 0) {

            if (mark && preserveMissMark) {
                if (!xstrtoui(&token[10], NULL, &preserveMissMarkMask, 0, std::numeric_limits<nfmark_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad mark miss-mark value " << &token[10]);
                    self_destruct();
                }
            } else if (preserveMissTos) {
                unsigned int v = 0;
                if (!xstrtoui(&token[10], NULL, &v, 0, std::numeric_limits<tos_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad TOS miss-mark value " << &token[10]);
                    self_destruct();
                }
                preserveMissTosMask = (tos_t)v;
            } else {
                debugs(3, DBG_CRITICAL, "ERROR: miss-mask feature cannot be set without miss-preservation enabled");
                self_destruct();
            }

        }
    }
}

/**
 * NOTE: Due to the low-level nature of the library these
 * objects are part of the dump function must be self-contained.
 * which means no StoreEntry refrences. Just a basic char* buffer.
*/
void
Ip::Qos::Config::dumpConfigLine(char *entry, const char *name) const
{
    char *p = entry;
    if (isHitTosActive()) {

        p += snprintf(p, 11, "%s", name); // strlen("qos_flows ");
        p += snprintf(p, 4, "%s", "tos");

        if (tosLocalHit > 0) {
            p += snprintf(p, 16, " local-hit=0x%02X", tosLocalHit);
        }
        if (tosSiblingHit > 0) {
            p += snprintf(p, 18, " sibling-hit=0x%02X", tosSiblingHit);
        }
        if (tosParentHit > 0) {
            p += snprintf(p, 17, " parent-hit=0x%02X", tosParentHit);
        }
        if (tosMiss > 0) {
            p += snprintf(p, 11, " miss=0x%02X", tosMiss);
            if (tosMissMask!=0xFFU) {
                p += snprintf(p, 6, "/0x%02X", tosMissMask);
            }
        }
        if (preserveMissTos == 0) {
            p += snprintf(p, 23, " disable-preserve-miss");
        }
        if (preserveMissTos && preserveMissTosMask != 0) {
            p += snprintf(p, 16, " miss-mask=0x%02X", preserveMissTosMask);
        }
        p += snprintf(p, 2, "\n");
    }

    if (isHitNfmarkActive()) {
        p += snprintf(p, 11, "%s", name); // strlen("qos_flows ");
        p += snprintf(p, 5, "%s", "mark");

        if (markLocalHit > 0) {
            p += snprintf(p, 22, " local-hit=0x%02X", markLocalHit);
        }
        if (markSiblingHit > 0) {
            p += snprintf(p, 24, " sibling-hit=0x%02X", markSiblingHit);
        }
        if (markParentHit > 0) {
            p += snprintf(p, 23, " parent-hit=0x%02X", markParentHit);
        }
        if (markMiss > 0) {
            p += snprintf(p, 17, " miss=0x%02X", markMiss);
            if (markMissMask!=0xFFFFFFFFU) {
                p += snprintf(p, 12, "/0x%02X", markMissMask);
            }
        }
        if (preserveMissMark == false) {
            p += snprintf(p, 23, " disable-preserve-miss");
        }
        if (preserveMissMark && preserveMissMarkMask != 0) {
            p += snprintf(p, 22, " miss-mask=0x%02X", preserveMissMarkMask);
        }
        p += snprintf(p, 2, "\n");
    }
}

#if !_USE_INLINE_
#include "Qos.cci"
#endif

