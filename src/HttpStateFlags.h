#ifndef SQUID_HTTPSTATEFLAGS_H_
#define SQUID_HTTPSTATEFLAGS_H_
/*
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

// POD
class HttpStateFlags
{
public:
    bool proxying:1;
    bool keepalive:1;
    bool only_if_cached:1;
    bool handling1xx:1; ///< we are ignoring or forwarding 1xx response
    bool headers_parsed:1;
    unsigned int front_end_https:2; //XXX: huh?
    bool originpeer:1;
    bool keepalive_broken:1;
    bool abuse_detected:1;
    bool request_sent:1;
    bool do_next_read:1;
    bool consume_body_data:1; //XXX: seems unused
    bool chunked:1; ///< reading a chunked response; TODO: rename
    bool chunked_request:1; ///< writing a chunked request
    bool sentLastChunk:1; ///< do not try to write last-chunk again
};

#endif /* SQUID_HTTPSTATEFLAGS_H_ */
