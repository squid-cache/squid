/*
 * DEBUG: section 37    ICMP Routines
 * AUTHOR: Duane Wessels, Amos Jeffries
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
#include "squid.h"
#include "Icmp.h"
#include "SquidTime.h"
#include "Debug.h"

Icmp::Icmp()
{
#if USE_ICMP
    icmp_sock = -1;
    icmp_ident = 0;
#endif
}

void
Icmp::Close()
{
#if USE_ICMP
    if (icmp_sock > 0)
        close(icmp_sock);
    icmp_sock = -1;
    icmp_ident = 0;
#endif
}

#if USE_ICMP

int
Icmp::CheckSum(unsigned short *ptr, int size)
{
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    if (!ptr) return (int)htons(0xffff); // bad input.

    sum = 0;

    while (size > 1) {
        sum += *ptr;
        ++ptr;
        size -= 2;
    }

    if (size == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short) ~sum;
    return (answer);
}

int
Icmp::ipHops(int ttl)
{
    if (ttl < 33)
        return 33 - ttl;

    if (ttl < 63)
        return 63 - ttl;        /* 62 = (64+60)/2 */

    if (ttl < 65)
        return 65 - ttl;        /* 62 = (64+60)/2 */

    if (ttl < 129)
        return 129 - ttl;

    if (ttl < 193)
        return 193 - ttl;

    return 256 - ttl;
}

void
Icmp::Log(const Ip::Address &addr, const uint8_t type, const char* pkt_str, const int rtt, const int hops)
{
    debugs(42, 2, "pingerLog: " << std::setw(9) << current_time.tv_sec  <<
           "." << std::setfill('0') << std::setw(6) <<
           current_time.tv_usec  << " " << std::left << std::setfill(' ') <<
           std::setw(45) << addr  << " " << type  <<
           " " << std::setw(15) << pkt_str << " " << rtt  <<
           "ms " << hops  << " hops");
}

#endif /* USE_ICMP */
