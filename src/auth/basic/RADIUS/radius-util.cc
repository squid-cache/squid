/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// 2008-05-14: rename to radius-util.* to avoid name clashes with squid util.*
/*
 *
 *  RADIUS
 *  Remote Authentication Dial In User Service
 *
 *
 *  Livingston Enterprises, Inc.
 *  6920 Koll Center Parkway
 *  Pleasanton, CA   94566
 *
 *  Copyright 1992 Livingston Enterprises, Inc.
 *  Copyright 1997 Cistron Internet Services B.V.
 *
 *  Permission to use, copy, modify, and distribute this software for any
 *  purpose and without fee is hereby granted, provided that this
 *  copyright and permission notice appear on all copies and supporting
 *  documentation, the name of Livingston Enterprises, Inc. not be used
 *  in advertising or publicity pertaining to distribution of the
 *  program without specific prior permission, and notice be given
 *  in supporting documentation that copying and distribution is by
 *  permission of Livingston Enterprises, Inc.
 *
 *  Livingston Enterprises, Inc. makes no representations about
 *  the suitability of this software for any purpose.  It is
 *  provided "as is" without express or implied warranty.
 *
 */

/*
 * util.c   Miscellanous generic functions.
 *
 */

char util_sccsid[] =
    "@(#)util.c	1.5 Copyright 1992 Livingston Enterprises Inc\n"
    "		2.1 Copyright 1997 Cistron Internet Services B.V.";

#include "squid.h"
#include "auth/basic/RADIUS/radius-util.h"
#include "md5.h"

#include <cctype>
#include <csignal>
#include <ctime>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif

/*
 *  Check for valid IP address in standard dot notation.
 */
static int good_ipaddr(char *addr)
{
    int dot_count;
    int digit_count;

    dot_count = 0;
    digit_count = 0;
    while (*addr != '\0' && *addr != ' ') {
        if (*addr == '.') {
            ++dot_count;
            digit_count = 0;
        } else if (!isdigit(*addr)) {
            dot_count = 5;
        } else {
            ++digit_count;
            if (digit_count > 3) {
                dot_count = 5;
            }
        }
        ++addr;
    }
    if (dot_count != 3) {
        return(-1);
    } else {
        return(0);
    }
}

/*
 *  Return an IP address in host long notation from
 *  one supplied in standard dot notation.
 */
static uint32_t ipstr2long(char *ip_str)
{
    char    buf[6];
    char    *ptr;
    int i;
    int count;
    uint32_t    ipaddr;
    int cur_byte;

    ipaddr = (uint32_t)0;
    for (i = 0; i < 4; ++i) {
        ptr = buf;
        count = 0;
        *ptr = '\0';
        while (*ip_str != '.' && *ip_str != '\0' && count < 4) {
            if (!isdigit(*ip_str)) {
                return((uint32_t)0);
            }
            *ptr = *ip_str;
            ++ptr;
            ++ip_str;
            ++count;
        }
        if (count >= 4 || count == 0) {
            return((uint32_t)0);
        }
        *ptr = '\0';
        cur_byte = atoi(buf);
        if (cur_byte < 0 || cur_byte > 255) {
            return((uint32_t)0);
        }
        ++ip_str;
        ipaddr = ipaddr << 8 | (uint32_t)cur_byte;
    }
    return(ipaddr);
}

/*
 *  Return an IP address in host long notation from a host
 *  name or address in dot notation.
 */
uint32_t get_ipaddr(char *host)
{
    struct hostent  *hp;

    if (good_ipaddr(host) == 0) {
        return(ipstr2long(host));
    } else if ((hp = gethostbyname(host)) == (struct hostent *)NULL) {
        return((uint32_t)0);
    }
    return(ntohl(*(uint32_t *)hp->h_addr));
}

