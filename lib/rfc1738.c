/*
 * $Id: rfc1738.c,v 1.5 1996/09/17 16:32:26 wessels Exp $
 *
 * DEBUG: 
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#include "util.h"
#define BIG_BUFSIZ (BUFSIZ * 4)

/*  
 *  RFC 1738 defines that these characters should be escaped, as well
 *  any non-US-ASCII character or anything between 0x00 - 0x1F.
 */
static char rfc1738_unsafe_chars[] =
{
    (char) 0x3C,		/* < */
    (char) 0x3E,		/* > */
    (char) 0x22,		/* " */
    (char) 0x23,		/* # */
    (char) 0x25,		/* % */
    (char) 0x7B,		/* { */
    (char) 0x7D,		/* } */
    (char) 0x7C,		/* | */
    (char) 0x5C,		/* \ */
    (char) 0x5E,		/* ^ */
    (char) 0x7E,		/* ~ */
    (char) 0x5B,		/* [ */
    (char) 0x5D,		/* ] */
    (char) 0x60,		/* ` */
    (char) 0x27,		/* ' */
    (char) 0x20			/* space */
};

/*
 *  rfc1738_escape - Returns a static buffer contains the RFC 1738 
 *  compliant, escaped version of the given url.
 */
char *
rfc1738_escape(char *url)
{
    static char buf[BIG_BUFSIZ];
    char *p, *q;
    int i, do_escape;

    for (p = url, q = &buf[0]; *p != '\0'; p++, q++) {
	do_escape = 0;

	/* RFC 1738 defines these chars as unsafe */
	for (i = 0; i < sizeof(rfc1738_unsafe_chars); i++) {
	    if (*p == rfc1738_unsafe_chars[i]) {
		do_escape = 1;
		break;
	    }
	}
	/* RFC 1738 says any control chars (0x00-0x1F) are encoded */
	if ((unsigned char) *p <= (unsigned char) 0x1F) {
	    do_escape = 1;
	}
	/* RFC 1738 says 0x7f is encoded */
	if (*p == (char) 0x7F) {
	    do_escape = 1;
	}
	/* RFC 1738 says any non-US-ASCII are encoded */
	if (((unsigned char) *p >= (unsigned char) 0x80) &&
	    ((unsigned char) *p <= (unsigned char) 0xFF)) {
	    do_escape = 1;
	}
	/* Do the triplet encoding, or just copy the char */
	if (do_escape == 1) {
	    (void) sprintf(q, "%%%02x", (unsigned char) *p);
	    q += sizeof(char) * 2;
	} else {
	    *q = *p;
	}
    }
    *q = '\0';
    return (buf);
}

/*
 *  rfc1738_unescape() - Converts escaped characters (%xy numbers) in 
 *  given the string.  %% is a %. %ab is the 8-bit hexadecimal number "ab"
 */
void
rfc1738_unescape(char *s)
{
    char hexnum[3];
    int i, j;			/* i is write, j is read */
    unsigned int x;

    for (i = j = 0; s[j]; i++, j++) {
	s[i] = s[j];
	if (s[i] == '%') {
	    hexnum[0] = s[++j];
	    if (hexnum[0] != '%') {
		hexnum[1] = s[++j];
		hexnum[2] = '\0';
		sscanf(hexnum, "%x", &x);
		s[i] = (char) (0x0ff & x);
	    } else {
		s[i] = '%';
	    }
	}
    }
    s[i] = '\0';
}
