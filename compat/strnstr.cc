#ifndef SQUID_COMPAT_STRNSTR_CC_
#define SQUID_COMPAT_STRNSTR_CC_

/*
 *  Shamelessly duplicated from the FreeBSD public sources
 *  for use by the Squid Project under GNU Public License.
 *
 * Update/Maintenance History:
 *
 *    26-Apr-2008 : Copied from FreeBSD via OpenGrok
 * 			- added protection around libray headers
 * 			- added squid_ prefix for uniqueness
 * 			  so we can use it where OS copy is broken.
 *
 *  Original License and code follows.
 */

#include "squid.h"

#if !HAVE_STRNSTR

/*-
 * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
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
 * @(#)strstr.c	8.1 (Berkeley) 6/4/93
 * $FreeBSD: src/lib/libc/string/strnstr.c,v 1.2.2.1 2001/12/09 06:50:03 mike Exp $
 * $DragonFly: src/lib/libc/string/strnstr.c,v 1.4 2006/03/20 17:24:20 dillon Exp $
 */

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

/**
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
const char *
squid_strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen < 1 || (sc = *s) == '\0')
                    return (NULL);
                --slen;
                ++s;
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        --s;
    }
    return s;
}

#endif /* !HAVE_STRNSTR */
#endif /* SQUID_COMPAT_STRNSTR_CC_ */
