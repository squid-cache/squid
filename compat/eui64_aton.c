/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Squid Change History:
 *
 *  2009-10-16 : import eui64_aton() function from NetBSD eui64.c
 */

/*      $NetBSD: eui64.c,v 1.1 2005/07/11 15:35:25 kiyohara Exp $       */
/*
 * Copyright 2004 The Aerospace Corporation.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions, and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions, and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  The name of The Aerospace Corporation may not be used to endorse or
 *     promote products derived from this software.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AEROSPACE CORPORATION "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AEROSPACE CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 1995
 *      Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * EUI-64 conversion and lookup routines
 *
 *
 * Converted from ether_addr.c rev
 * FreeBSD: src/lib/libc/net/eui64.c,v 1.15 2002/04/08 07:51:10 ru Exp
 * by Brooks Davis
 *
 * Written by Bill Paul <wpaul@ctr.columbia.edu>
 * Center for Telecommunications Research
 * Columbia University, New York City
 */

#include "squid.h"
#include "compat/eui64_aton.h"

#if SQUID_EUI64_ATON

/*
 * Convert an ASCII representation of an EUI-64 to binary form.
 */
int
eui64_aton(const char *a, struct eui64 *e)
{
    int i;
    unsigned int o0, o1, o2, o3, o4, o5, o6, o7;

    /* canonical form */
    i = sscanf(a, "%x-%x-%x-%x-%x-%x-%x-%x",
               &o0, &o1, &o2, &o3, &o4, &o5, &o6, &o7);
    if (i == EUI64_LEN)
        goto good;
    /* ethernet form */
    i = sscanf(a, "%x:%x:%x:%x:%x:%x:%x:%x",
               &o0, &o1, &o2, &o3, &o4, &o5, &o6, &o7);
    if (i == EUI64_LEN)
        goto good;
    /* classic fwcontrol/dconschat form */
    i = sscanf(a, "0x%2x%2x%2x%2x%2x%2x%2x%2x",
               &o0, &o1, &o2, &o3, &o4, &o5, &o6, &o7);
    if (i == EUI64_LEN)
        goto good;
    /* MAC format (-) */
    i = sscanf(a, "%x-%x-%x-%x-%x-%x",
               &o0, &o1, &o2, &o5, &o6, &o7);
    if (i == 6) {
        o3 = 0xff;
        o4 = 0xfe;
        goto good;
    }
    /* MAC format (:) */
    i = sscanf(a, "%x:%x:%x:%x:%x:%x",
               &o0, &o1, &o2, &o5, &o6, &o7);
    if (i == 6) {
        o3 = 0xff;
        o4 = 0xfe;
        goto good;
    }

    return (-1);

good:
    e->octet[0]=o0;
    e->octet[1]=o1;
    e->octet[2]=o2;
    e->octet[3]=o3;
    e->octet[4]=o4;
    e->octet[5]=o5;
    e->octet[6]=o6;
    e->octet[7]=o7;

    return (0);
}

#endif /* !SQUID_EUI64_ATON */

