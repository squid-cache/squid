/*
 * $Id: mime.cc,v 1.25 1996/11/25 06:15:31 wessels Exp $
 *
 * DEBUG: section 25    MIME Parsing
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
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

#include "squid.h"
#include "mime_table.h"

#define GET_HDR_SZ 1024

char *
mime_get_header(const char *mime, const char *name)
{
    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *p = NULL;
    char *q = NULL;
    char got = 0;
    int namelen = strlen(name);
    int l;

    if (!mime || !name)
	return NULL;

    debug(25, 5, "mime_get_header: looking for '%s'\n", name);

    for (p = mime; *p; p += strcspn(p, "\n\r")) {
	if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
	    return NULL;
	while (isspace(*p))
	    p++;
	if (strncasecmp(p, name, namelen))
	    continue;
	if (!isspace(p[namelen]) && p[namelen] != ':')
	    continue;
	l = strcspn(p, "\n\r") + 1;
	if (l > GET_HDR_SZ)
	    l = GET_HDR_SZ;
	xstrncpy(header, p, l);
	debug(25, 5, "mime_get_header: checking '%s'\n", header);
	q = header;
	q += namelen;
	if (*q == ':')
	    q++, got = 1;
	while (isspace(*q))
	    q++, got = 1;
	if (got) {
	    debug(25, 5, "mime_get_header: returning '%s'\n", q);
	    return q;
	}
    }
    return NULL;
}

/* need to take the lowest, non-zero pointer to the end of the headers.
 * The headers end at the first empty line */
char *
mime_headers_end(const char *mime)
{
    const char *p1, *p2;
    const char *end = NULL;

    p1 = strstr(mime, "\r\n\r\n");
    p2 = strstr(mime, "\n\n");

    if (p1 && p2)
	end = p1 < p2 ? p1 : p2;
    else
	end = p1 ? p1 : p2;
    if (end)
	end += (end == p1 ? 4 : 2);

    return (char *) end;
}

int
mime_headers_size(const char *mime)
{
    const char *end;

    end = mime_headers_end(mime);

    if (end)
	return end - mime;
    else
	return 0;
}

const ext_table_entry *
mime_ext_to_type(const char *extension)
{
    int i;
    int low;
    int high;
    int comp;
    LOCAL_ARRAY(char, ext, 16);
    char *cp = NULL;

    if (!extension || strlen(extension) >= (sizeof(ext) - 1))
	return NULL;
    strcpy(ext, extension);
    for (cp = ext; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);
    low = 0;
    high = EXT_TABLE_LEN - 1;
    while (low <= high) {
	i = (low + high) / 2;
	if ((comp = strcmp(ext, ext_mime_table[i].name)) == 0)
	    return &ext_mime_table[i];
	if (comp > 0)
	    low = i + 1;
	else
	    high = i - 1;
    }
    return NULL;
}

/*
 *  mk_mime_hdr - Generates a MIME header using the given parameters.
 *  You can call mk_mime_hdr with a 'lmt = time(NULL) - ttl' to
 *  generate a fake Last-Modified-Time for the header.
 *  'ttl' is the number of seconds relative to the current time
 *  that the object is valid.
 *
 *  Returns the MIME header in the provided 'result' buffer, and
 *  returns non-zero on error, or 0 on success.
 */
int
mk_mime_hdr(char *result, const char *type, int size, time_t ttl, time_t lmt)
{
    time_t expiretime;
    time_t t;
    LOCAL_ARRAY(char, date, 100);
    LOCAL_ARRAY(char, expires, 100);
    LOCAL_ARRAY(char, last_modified, 100);
    LOCAL_ARRAY(char, content_length, 100);

    if (result == NULL)
	return 1;
    t = squid_curtime;
    expiretime = ttl ? t + ttl : 0;
    date[0] = expires[0] = last_modified[0] = '\0';
    content_length[0] = result[0] = '\0';
    sprintf(date, "Date: %s\r\n", mkrfc1123(t));
    if (ttl >= 0)
	sprintf(expires, "Expires: %s\r\n", mkrfc1123(expiretime));
    if (lmt)
	sprintf(last_modified, "Last-Modified: %s\r\n", mkrfc1123(lmt));
    if (size > 0)
	sprintf(content_length, "Content-Length: %d\r\n", size);
    sprintf(result, "Server: %s/%s\r\n%s%s%sContent-Type: %s\r\n%s",
	appname,
	version_string,
	date,
	expires,
	last_modified,
	type,
	content_length);
    return 0;
}
