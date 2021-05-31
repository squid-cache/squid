/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_EUI64_ATON_H
#define SQUID_COMPAT_EUI64_ATON_H

/* If we have this system file use it. Otherwise use the below definitions. */
#if HAVE_SYS_EUI64_H
#include <sys/eui64.h>
#else

/*
 * Squid Change History:
 *
 *  2009-10-16 : import from NetBSD eui64.c.
 *               strip definitions not required by eui64_aton()
 */

/*      $NetBSD: eui64.h,v 1.1 2005/07/11 15:35:25 kiyohara Exp $       */
/*-
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
 * $FreeBSD: /repoman/r/ncvs/src/sys/sys/eui64.h,v 1.2 2005/01/07 02:29:23 imp Exp $
 */
#ifndef _SYS_EUI64_H
#define _SYS_EUI64_H
#if defined(__cplusplus)
extern "C" {
#endif

#define SQUID_EUI64_ATON 1

/**
 * Size of the ASCII representation of an EUI-64.
 */
#define EUI64_SIZ       24

/**
 * The number of bytes in an EUI-64.
 */
#define EUI64_LEN       8

/**
 * Structure of an IEEE EUI-64.
 */
struct eui64 {
    uint8_t octet[EUI64_LEN];
};

int eui64_aton(const char *a, struct eui64 *e);
#if defined(__cplusplus)
}
#endif

#endif /* !_SYS_EUI64_H */
#endif /* HAVE_SYS_EUI64_H */
#endif /* SQUID_COMPAT_EUI64_ATON_H */

