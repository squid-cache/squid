
/*
 * $Id: http.h,v 1.2 2002/10/14 08:16:58 robertc Exp $
 *
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

#ifndef SQUID_HTTP_H
#define SQUID_HTTP_H

#include "StoreIOBuffer.h"
#include "comm.h"

class HttpStateData {
    public:
    void processReplyHeader(const char *, int);
    void processReplyData(const char *, int);
    IOCB readReply;
    void maybeReadData();

    StoreEntry *entry;
    request_t *request;
    char *reply_hdr;
    size_t reply_hdr_size;
    int reply_hdr_state;
    peer *_peer;		/* peer request made to */
    int eof;			/* reached end-of-object? */
    request_t *orig_request;
    int fd;
    http_state_flags flags;
    FwdState *fwd;
    int do_next_read;
    size_t read_sz;
    char buf[SQUID_TCP_SO_RCVBUF];
};

#endif /* SQUID_HTTP_H */
