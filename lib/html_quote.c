/*
 * $Id: html_quote.c,v 1.2 2000/11/21 21:14:44 wessels Exp $
 * 
 * DEBUG:
 * AUTHOR: Robert Collins
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#include "util.h"
#include "snprintf.h"

/*  
 *  HTML defines these characters as special entities that should be quoted.
 */
static struct {
    unsigned char code;
    char *quote;
} htmlstandardentities[] =

{
    /* NOTE: The quoted form MUST not be larger than 6 character.
     * see close to the MemPool commend below
     */
    {
	'<', "&lt;"
    },
    {
	'>', "&gt;"
    },
    {
	'"', "&quot;"
    },
    {
	'&', "&amp;"
    },
    {
	'\'', "&#39;"
    },
    {
	0, NULL
    }
};

/*
 *  html_do_quote - Returns a static buffer containing the quoted 
 *  string.
 */
char *
html_quote(const char *string)
{
    static char *buf;
    static size_t bufsize = 0;
    const char *src;
    char *dst;
    int i;

    /* XXX This really should be implemented using a MemPool, but
     * MemPools are not yet available in lib...
     */
    if (buf == NULL || strlen(string) * 6 > bufsize) {
	xfree(buf);
	bufsize = strlen(string) * 6 + 1;
	buf = xcalloc(bufsize, 1);
    }
    for (src = string, dst = buf; *src; src++) {
	char *escape = NULL;
	const unsigned char ch = *src;

	/* Walk thru the list of HTML Entities that must be quoted to
	 * display safely
	 */
	for (i = 0; htmlstandardentities[i].code; i++) {
	    if (ch == htmlstandardentities[i].code) {
		escape = htmlstandardentities[i].quote;
		break;
	    }
	}
	/* Encode control chars just to be on the safe side, and make
	 * sure all 8-bit characters are encoded to protect from buggy
	 * clients
	 */
	if (!escape && (ch <= 0x1F || ch >= 0x7f) && ch != '\n' && ch != '\r' && ch != '\t') {
	    static char dec_encoded[7];
	    snprintf(dec_encoded, sizeof dec_encoded, "&#%3d;", (int) ch);
	    escape = dec_encoded;
	}
	if (escape) {
	    /* Ok, An escaped form was found above. Use it */
	    strncpy(dst, escape, 6);
	    dst += strlen(escape);
	} else {
	    /* Apparently there is no need to escape this character */
	    *dst++ = ch;
	}
    }
    /* Nullterminate and return the result */
    *dst = '\0';
    return (buf);
}
