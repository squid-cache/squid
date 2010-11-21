#include "squid.h"

#include "acl/Gadgets.h"
#include "ConfigParser.h"
#include "fde.h"
#include "hier_code.h"
#include "ip/tools.h"
#include "ip/QosConfig.h"
#include "Parsing.h"

/* Qos namespace */

void
Ip::Qos::getTosFromServer(const int server_fd, fde *clientFde)
{
#if USE_QOS_TOS && _SQUID_LINUX_
    /* Bug 2537: This part of ZPH only applies to patched Linux kernels. */
    tos_t tos = 1;
    int tos_len = sizeof(tos);
    clientFde->tosFromServer = 0;
    if (setsockopt(server_fd,SOL_IP,IP_RECVTOS,&tos,tos_len)==0) {
        unsigned char buf[512];
        int len = 512;
        if (getsockopt(server_fd,SOL_IP,IP_PKTOPTIONS,buf,(socklen_t*)&len) == 0) {
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
                    int *tmp = (int*)CMSG_DATA(o);
                    clientFde->tosFromServer = (tos_t)*tmp;
                    break;
                }
                pbuf += CMSG_LEN(o->cmsg_len);
            }
        } else {
            debugs(33, 1, "QOS: error in getsockopt(IP_PKTOPTIONS) on FD " << server_fd << " " << xstrerror());
        }
    } else {
        debugs(33, 1, "QOS: error in setsockopt(IP_RECVTOS) on FD " << server_fd << " " << xstrerror());
    }
#endif
}

void Ip::Qos::getNfmarkFromServer(const int server_fd, const fde *servFde, const fde *clientFde)
{
#if USE_LIBNETFILTERCONNTRACK
    /* Allocate a new conntrack */
    if (struct nf_conntrack *ct = nfct_new()) {

        /* Prepare data needed to find the connection in the conntrack table.
         * We need the local and remote IP address, and the local and remote
         * port numbers.
         */

        Ip::Address serv_fde_local_conn;
        struct addrinfo *addr = NULL;
        serv_fde_local_conn.InitAddrInfo(addr);
        getsockname(server_fd, addr->ai_addr, &(addr->ai_addrlen));
        serv_fde_local_conn = *addr;
        serv_fde_local_conn.GetAddrInfo(addr);

        unsigned short serv_fde_local_port = ((struct sockaddr_in*)addr->ai_addr)->sin_port;
        struct in6_addr serv_fde_local_ip6;
        struct in_addr serv_fde_local_ip;

        if (Ip::EnableIpv6 && serv_fde_local_conn.IsIPv6()) {
            serv_fde_local_ip6 = ((struct sockaddr_in6*)addr->ai_addr)->sin6_addr;
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
            struct in6_addr serv_fde_remote_ip6;
            inet_pton(AF_INET6,servFde->ipaddr,(struct in6_addr*)&serv_fde_remote_ip6);
            nfct_set_attr(ct, ATTR_IPV6_DST, serv_fde_remote_ip6.s6_addr);
            nfct_set_attr(ct, ATTR_IPV6_SRC, serv_fde_local_ip6.s6_addr);
        } else {
            serv_fde_local_ip = ((struct sockaddr_in*)addr->ai_addr)->sin_addr;
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
            nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr(servFde->ipaddr));
            nfct_set_attr_u32(ct, ATTR_IPV4_SRC, serv_fde_local_ip.s_addr);
        }

        nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
        nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(servFde->remote_port));
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, serv_fde_local_port);

        /* Open a handle to the conntrack */
        if (struct nfct_handle *h = nfct_open(CONNTRACK, 0)) {
            /* Register the callback. The callback function will record the mark value. */
            nfct_callback_register(h, NFCT_T_ALL, getNfMarkCallback, (void *)clientFde);
            /* Query the conntrack table using the data previously set */
            int x = nfct_query(h, NFCT_Q_GET, ct);
            if (x == -1) {
                debugs(17, 2, "QOS: Failed to retrieve connection mark: (" << x << ") " << strerror(errno)
                       << " (Destination " << servFde->ipaddr << ":" << servFde->remote_port
                       << ", source " << serv_fde_local_conn << ")" );
            }

            nfct_close(h);
        } else {
            debugs(17, 2, "QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
        serv_fde_local_conn.FreeAddrInfo(addr);
        nfct_destroy(ct);

    } else {
        debugs(17, 2, "QOS: Failed to allocate new conntrack for upstream netfilter mark retrieval.");
    }
#endif
}

#if USE_LIBNETFILTERCONNTRACK
int
Ip::Qos::getNfMarkCallback(enum nf_conntrack_msg_type type,
                           struct nf_conntrack *ct,
                           void *data)
{
    fde *clientFde = (fde *)data;
    clientFde->nfmarkFromServer = nfct_get_attr_u32(ct, ATTR_MARK);
    debugs(17, 3, "QOS: Retrieved connection mark value: " << clientFde->nfmarkFromServer);

    return NFCT_CB_CONTINUE;
}
#endif

int
Ip::Qos::doTosLocalMiss(const int fd, const hier_code hierCode)
{
    tos_t tos = 0;
    if (Ip::Qos::TheConfig.tosSiblingHit && hierCode==SIBLING_HIT) {
        tos = Ip::Qos::TheConfig.tosSiblingHit;
        debugs(33, 2, "QOS: Sibling Peer hit with hier code=" << hierCode << ", TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.tosParentHit && hierCode==PARENT_HIT) {
        tos = Ip::Qos::TheConfig.tosParentHit;
        debugs(33, 2, "QOS: Parent Peer hit with hier code=" << hierCode << ", TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.tosMiss) {
        tos = Ip::Qos::TheConfig.tosMiss;
        debugs(33, 2, "QOS: Cache miss, setting TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.preserveMissTos && Ip::Qos::TheConfig.preserveMissTosMask) {
        tos = fd_table[fd].tosFromServer & Ip::Qos::TheConfig.preserveMissTosMask;
        debugs(33, 2, "QOS: Preserving TOS on miss, TOS=" << int(tos));
    }
    return setSockTos(fd, tos);
}

int
Ip::Qos::doNfmarkLocalMiss(const int fd, const hier_code hierCode)
{
    nfmark_t mark = 0;
    if (Ip::Qos::TheConfig.markSiblingHit && hierCode==SIBLING_HIT) {
        mark = Ip::Qos::TheConfig.markSiblingHit;
        debugs(33, 2, "QOS: Sibling Peer hit with hier code=" << hierCode << ", Mark=" << mark);
    } else if (Ip::Qos::TheConfig.markParentHit && hierCode==PARENT_HIT) {
        mark = Ip::Qos::TheConfig.markParentHit;
        debugs(33, 2, "QOS: Parent Peer hit with hier code=" << hierCode << ", Mark=" << mark);
    } else if (Ip::Qos::TheConfig.markMiss) {
        mark = Ip::Qos::TheConfig.markMiss;
        debugs(33, 2, "QOS: Cache miss, setting Mark=" << mark);
    } else if (Ip::Qos::TheConfig.preserveMissMark) {
        mark = fd_table[fd].nfmarkFromServer & Ip::Qos::TheConfig.preserveMissMarkMask;
        debugs(33, 2, "QOS: Preserving mark on miss, Mark=" << mark);
    }
    return setSockNfmark(fd, mark);
}

int
Ip::Qos::doTosLocalHit(const int fd)
{
    debugs(33, 2, "QOS: Setting TOS for local hit, TOS=" << int(Ip::Qos::TheConfig.tosLocalHit));
    return setSockTos(fd, Ip::Qos::TheConfig.tosLocalHit);
}

int
Ip::Qos::doNfmarkLocalHit(const int fd)
{
    debugs(33, 2, "QOS: Setting netfilter mark for local hit, mark=" << Ip::Qos::TheConfig.markLocalHit);
    return setSockNfmark(fd, Ip::Qos::TheConfig.markLocalHit);
}

/* Qos::Config class */

Ip::Qos::Config Ip::Qos::TheConfig;

Ip::Qos::Config::Config()
{
    tosLocalHit = 0;
    tosSiblingHit = 0;
    tosParentHit = 0;
    tosMiss = 0;
    preserveMissTos = false;
    preserveMissTosMask = 0xFF;
    markLocalHit = 0;
    markSiblingHit = 0;
    markParentHit = 0;
    markMiss = 0;
    preserveMissMark = false;
    preserveMissMarkMask = 0xFFFFFFFF;
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

    while ( (token = strtok(NULL, w_space)) ) {

        // Work out TOS or mark. Default to TOS for backwards compatibility
        if (!(mark || tos)) {
            if (strncmp(token, "mark",4) == 0) {
#if SO_MARK
                mark = true;
                // Assume preserve is true. We don't set at initialisation as this affects isHitNfmarkActive()
#if USE_LIBNETFILTERCONNTRACK
                preserveMissMark = true;
# else // USE_LIBNETFILTERCONNTRACK
                preserveMissMark = false;
                debugs(3, DBG_IMPORTANT, "WARNING: Squid not compiled with Netfilter conntrack library. "
                       << "Netfilter mark preservation not available.");
#endif // USE_LIBNETFILTERCONNTRACK
#else // SO_MARK
                debugs(3, DBG_CRITICAL, "ERROR: Invalid parameter 'mark' in qos_flows option. "
                       << "Linux Netfilter marking not available.");
                self_destruct();
#endif // SO_MARK
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

            if (mark) {
                if (!xstrtoui(&token[5], NULL, &markMiss, 0, std::numeric_limits<nfmark_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad mark miss value " << &token[5]);
                    self_destruct();
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[5], NULL, &v, 0, std::numeric_limits<tos_t>::max())) {
                    debugs(3, DBG_CRITICAL, "ERROR: Bad TOS miss value " << &token[5]);
                    self_destruct();
                }
                tosMiss = (tos_t)v;
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
