/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 89    EUI-64 Handling */

#include "squid.h"

#if USE_SQUID_EUI

#if _SQUID_LINUX_
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include "compat/eui64_aton.h"
#include "Debug.h"
#include "eui/Eui64.h"
#include "globals.h"
#include "ip/Address.h"

bool
Eui::Eui64::decode(const char *asc)
{
    if (eui64_aton(asc, (struct eui64 *)eui) != 0) {
        debugs(28, 4, "id=" << (void*)this << " decode fail on " << asc);
        return false;
    }

    debugs(28, 4, "id=" << (void*)this << " ATON decoded " << asc);
    return true;
}

bool
Eui::Eui64::encode(char *buf, const int len) const
{
    if (len < SZ_EUI64_BUF) return false;

    snprintf(buf, len, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
             eui[0], eui[1], eui[2], eui[3],
             eui[4], eui[5], eui[6], eui[7]);
    debugs(28, 4, "id=" << (void*)this << " encoded " << buf);
    return true;
}

// return binary representation of the EUI
bool
Eui::Eui64::lookup(const Ip::Address &c)
{
    /* try to short-circuit slow OS lookups by using SLAAC data */
    if (lookupSlaac(c))
        return true;

    // find EUI-64 some other way. NDP table lookup?
    return lookupNdp(c);
}

bool
Eui::Eui64::lookupSlaac(const Ip::Address &c)
{
    /* RFC 4291 Link-Local unicast addresses which contain SLAAC - usually trustable. */
    if (c.isSiteLocal6() && c.isSiteLocalAuto()) {

        // strip the final 64 bits of the address...
        struct in6_addr tmp;
        c.getInAddr(tmp);
        memcpy(eui, &(tmp.s6_addr[8]), SZ_EUI64_BUF);
        debugs(28, 4, "id=" << (void*)this << " SLAAC decoded " << c);
        return true;
    }

    debugs(28, 4, "id=" << (void*)this << " SLAAC fail on " << c << " SL-6="
           << (c.isSiteLocal6()?'T':'F') << " AAC-6=" << (c.isSiteLocalAuto()?'T':'F'));
    return false;
}

// return binary representation of the EUI
bool
Eui::Eui64::lookupNdp(const Ip::Address &c)
{
    bool success = false;

#if _SQUID_LINUX_
    int rtnetlink_sock;
    struct {
        struct nlmsghdr hdr;
        struct ndmsg ndm;
    } req;
    struct sockaddr_nl sa;
    struct iovec iov;
    struct msghdr msg;
    char buf[16384];
    ssize_t buff_fill;
    struct nlmsghdr * nl_reply_hdr;
    struct nlmsghdr * nl_reply_msg;
    struct rtattr * rt_reply_attr;
    size_t rt_reply_len;
    bool found_ip = 0;
    bool done = 0;
    struct in6_addr ip;
    void * mac_ptr;

    c.getInAddr(ip);

    // Prepare rtnetlink request
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.hdr.nlmsg_type = RTM_GETNEIGH;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 0;
    req.hdr.nlmsg_pid = 0;
    req.ndm.ndm_family = AF_INET6;
    req.ndm.ndm_state = 0;

    iov.iov_base = &req;
    iov.iov_len = req.hdr.nlmsg_len;

    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    // Send rtnetlink request
    rtnetlink_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtnetlink_sock >= 0) {
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        if (sendmsg(rtnetlink_sock, &msg, 0) >= 0) {
            // Loop through all the responses
            while ((! done) && ((buff_fill = recv(rtnetlink_sock, buf, sizeof(buf), 0)) >= 0)) {
                mac_ptr = NULL;
                for (nl_reply_hdr = (struct nlmsghdr *) buf; (! done) && NLMSG_OK(nl_reply_hdr, buff_fill); nl_reply_hdr = NLMSG_NEXT(nl_reply_hdr, buff_fill)) {
                    if (nl_reply_hdr->nlmsg_type == NLMSG_DONE) done = 1;
                    else if (nl_reply_hdr->nlmsg_type == RTM_NEWNEIGH) {
                        nl_reply_msg = (struct nlmsghdr *) NLMSG_DATA(nl_reply_hdr);
                        rt_reply_len = RTM_PAYLOAD(nl_reply_hdr);

                        for (rt_reply_attr = RTM_RTA(nl_reply_msg); (! done) && RTA_OK(rt_reply_attr, rt_reply_len); rt_reply_attr = RTA_NEXT(rt_reply_attr, rt_reply_len)) {
                            if (rt_reply_attr->rta_type == NDA_DST) {
                                if (memcmp(ip.s6_addr, RTA_DATA(rt_reply_attr), 16)) {
                                    // IP doesn't match - don't loop through the rest of the RTAs
                                    break;
                                } else found_ip = 1;
                            } else if (rt_reply_attr->rta_type == NDA_LLADDR) mac_ptr = RTA_DATA(rt_reply_attr);

                            if (found_ip && mac_ptr) {
                                // We've found the right IP and its MAC address.
                                // Insert 0xfffe to turn the MAC (EUI48) into an EUI64.
                                memcpy(eui, mac_ptr, 3);
                                eui[3] = 0xff;
                                eui[4] = 0xfe;
                                memcpy(eui+5, ((char *) mac_ptr) + 3, 3);
                                done = 1;
                                success = 1;
                            }
                        }
                    }
                }
            }
        }
        close(rtnetlink_sock);
    }
    if (! success) debugs(28, 4, "id=" << (void*)this << " NDP Fail on " << c);
#else
    debugs(28, DBG_CRITICAL, "ERROR: ARP / MAC / EUI-* operations not supported on this operating system.");
#endif

    if (! success) clear();
    return success;
}

#endif /* USE_SQUID_EUI */
