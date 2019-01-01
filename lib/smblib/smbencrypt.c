/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Unix SMB/Netbios implementation.
 * Version 1.9.
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1997
 * Modified by Jeremy Allison 1995.
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "squid.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>

/* AI inclusion for Solaris filesystem */
#ifdef SOLARIS
#include <sys/vfs.h>
#endif

#include "smblib/smblib-priv.h"
#define uchar unsigned char

#include "rfcnb/byteorder.h"

#include "smblib/md4.h"
#include "smblib/smbdes.h"
#include "smblib/smbencrypt.h"

static void E_md4hash(unsigned char *passwd, unsigned char *p16);
static char *StrnCpy(char *dest, char *src, int n);
static void strupper(char *s);

/*
 * This implements the X/Open SMB password encryption
 * It takes a password, a 8 byte "crypt key" and puts 24 bytes of
 * encrypted password into p24 */
void
SMBencrypt(uchar * passwd, uchar * c8, uchar * p24)
{
    uchar p14[15], p21[21];

    memset(p21, '\0', 21);
    memset(p14, '\0', 14);
    StrnCpy((char *) p14, (char *) passwd, 14);

    strupper((char *) p14);
    E_P16(p14, p21);
    E_P24(p21, c8, p24);
}

/* Routines for Windows NT MD4 Hash functions. */
static int
_my_wcslen(int16_t * str)
{
    int len = 0;
    while (*str++ != 0)
        len++;
    return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type
 * this must be in intel (little-endian)
 * format.
 */

static int
_my_mbstowcs(int16_t * dst, uchar * src, int len)
{
    int i;
    int16_t val;

    for (i = 0; i < len; i++) {
        val = *src;
        SSVAL(dst, 0, val);
        dst++;
        src++;
        if (val == 0)
            break;
    }
    return i;
}

/*
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */

void
E_md4hash(uchar * passwd, uchar * p16)
{
    int len;
    int16_t wpwd[129];

    /* Password cannot be longer than 128 characters */
    len = strlen((char *) passwd);
    if (len > 128)
        len = 128;
    /* Password must be converted to NT unicode */
    _my_mbstowcs(wpwd, passwd, len);
    wpwd[len] = 0;      /* Ensure string is null terminated */
    /* Calculate length in bytes */
    len = _my_wcslen(wpwd) * sizeof(int16_t);

    mdfour(p16, (unsigned char *) wpwd, len);
}

/* Does the NT MD4 hash then des encryption. */

void
SMBNTencrypt(uchar * passwd, uchar * c8, uchar * p24)
{
    uchar p21[21];

    memset(p21, '\0', 21);

    E_md4hash(passwd, p21);
    E_P24(p21, c8, p24);
}

/* Does both the NT and LM owfs of a user's password */

void
nt_lm_owf_gen(char *pwd, char *nt_p16, char *p16)
{
    char passwd[130];
    StrnCpy(passwd, pwd, sizeof(passwd) - 1);

    /* Calculate the MD4 hash (NT compatible) of the password */
    memset(nt_p16, '\0', 16);
    E_md4hash((uchar *) passwd, (uchar *) nt_p16);

    /* Mangle the passwords into Lanman format */
    passwd[14] = '\0';
    strupper(passwd);

    /* Calculate the SMB (lanman) hash functions of the password */

    memset(p16, '\0', 16);
    E_P16((uchar *) passwd, (uchar *) p16);

    /* clear out local copy of user's password (just being paranoid). */
    memset(passwd, 0, sizeof(passwd));
}

/****************************************************************************
line strncpy but always null terminates. Make sure there is room!
****************************************************************************/
char *
StrnCpy(char *dest, char *src, int n)
{
    char *d = dest;
    if (!dest)
        return (NULL);
    if (!src) {
        *dest = 0;
        return (dest);
    }
    while (n-- && (*d++ = *src++));
    *d = 0;
    return (dest);
}

void
strupper(char *s)
{
    while (*s) {
#if UNUSED_CODE
#if !defined(KANJI_WIN95_COMPATIBILITY)
        if (lp_client_code_page() == KANJI_CODEPAGE) {

            if (is_shift_jis(*s)) {
                if (is_sj_lower(s[0], s[1]))
                    s[1] = sj_toupper2(s[1]);
                s += 2;
            } else if (is_kana(*s)) {
                s++;
            } else {
                if (islower((int)(unsigned char)*s))
                    *s = toupper((int)(unsigned char)*s);
                s++;
            }
        } else
#endif /* KANJI_WIN95_COMPATIBILITY */
#endif /* UNUSED_CODE */
        {
            if (islower((int)(unsigned char)*s))
                *s = toupper((int)(unsigned char)*s);
            s++;
        }
    }
}

