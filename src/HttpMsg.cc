
/*
 * $Id: HttpMsg.cc,v 1.2 1998/05/27 22:51:43 rousskov Exp $
 *
 * DEBUG: section 74    HTTP Message
 * AUTHOR: Alex Rousskov
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

#include "squid.h"


/* find end of headers */
int
httpMsgIsolateHeaders(const char **parse_start, const char **blk_start, const char **blk_end)
{
    /* adopted with mods from mime_headers_end() */
    const char *p1 = strstr(*parse_start, "\n\r\n");
    const char *p2 = strstr(*parse_start, "\n\n");
    const char *end = NULL;

    if (p1 && p2)
	end = p1 < p2 ? p1 : p2;
    else
	end = p1 ? p1 : p2;

    if (end) {
	*blk_start = *parse_start;
	*blk_end = end + 1;
	*parse_start = end + (end == p1 ? 3 : 2);
	return 1;
    }
    /* no headers, case 1 */
    if ((*parse_start)[0] == '\r' && (*parse_start)[1] == '\n') {
	*blk_start = *parse_start;
	*blk_end = *blk_start;
	*parse_start += 2;
	return 1;
    }
    /* no headers, case 2 */
    if ((*parse_start)[0] == '\n') {
	/* no headers */
	*blk_start = *parse_start;
	*blk_end = *blk_start;
	*parse_start += 1;
	return 1;
    }
    /* failure */
    return 0;
}

/* returns true if connection should be "persistent" 
 * after processing this message */
int
httpMsgIsPersistent(float http_ver, const HttpHeader * hdr)
{
    if (http_ver >= 1.1) {
	/*
	 * for modern versions of HTTP: persistent unless there is
	 * a "Connection: close" header.
	 */
	return !httpHeaderHasConnDir(hdr, "close");
    } else {
	/*
	 * Persistent connections in Netscape 3.x are allegedly broken,
	 * return false if it is a browser connection.  If there is a
	 * VIA header, then we assume this is NOT a browser connection.
	 */
	const char *agent = httpHeaderGetStr(hdr, HDR_USER_AGENT);
	if (agent && !httpHeaderHas(hdr, HDR_VIA)) {
	    if (!strncasecmp(agent, "Mozilla/3.", 10))
		return 0;
	    if (!strncasecmp(agent, "Netscape/3.", 11))
		return 0;
	}
	/* for old versions of HTTP: persistent if has "keep-alive" */
	return httpHeaderHasConnDir(hdr, "keep-alive");
    }
}
