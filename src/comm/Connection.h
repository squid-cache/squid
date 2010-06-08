/*
 * DEBUG: section 05    Socket Functions
 * AUTHOR: Amos Jeffries
 * AUTHOR: Robert Collins
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 * Copyright (c) 2010, Amos Jeffries <amosjeffries@squid-cache.org>
 */

#ifndef _SQUIDCONNECTIONDETAIL_H_
#define _SQUIDCONNECTIONDETAIL_H_

#include "hier_code.h"
#include "ip/Address.h"
#include "RefCount.h"

struct peer;

namespace Comm {

/** COMM flags */
/* TODO: make these a struct of boolean flags in connection instead of a bitmap. */
#define COMM_UNSET              0x00
#define COMM_NONBLOCKING        0x01
#define COMM_NOCLOEXEC          0x02
#define COMM_REUSEADDR          0x04
#define COMM_TRANSPARENT        0x08
#define COMM_DOBIND             0x10

/**
 * Store data about the physical and logical attributes of a connection.
 *
 * Some link state can be infered from the data, however this is not an
 * object for state data. But a semantic equivalent for FD with easily
 * accessible cached properties not requiring repeated complex lookups.
 *
 * While the properties may be changed, they should be considered read-only
 * outside of the Comm layer code.
 *
 * These objects must not be passed around directly,
 * but a Comm::ConnectionPointer must be passed instead.
 */
class Connection : public RefCountable
{
public:
    /** standard empty connection creation */
    Connection();

    /** Clear the conection properties and close any open socket. */
    ~Connection();

    /** Clone an existing connections properties.
     * This includes the FD, if one is open its a good idea to set it to -1 (unopen)
     * on one after copying to prevent both clones calling comm_close() when destructed.
     */
    Connection(const Connection &c);
    /** see Comm::Connection::Connection */
    const Connection & operator =(const Connection &c);

    /** Address/Port for the Squid end of a TCP link. */
    Ip::Address local;

    /** Address for the Remote end of a TCP link. */
    Ip::Address remote;

    /** Hierarchy code for this connection link */
    hier_code peer_type;

    /** Socket used by this connection. -1 if no socket has been opened. */
    int fd;

    /** Quality of Service TOS values currently sent on this connection */
    int tos;

    /** COMM flags set on this connection */
    int flags;

    /** retrieve the peer pointer for use.
     * The caller is responsible for all CBDATA operations regarding the
     * used of the pointer returned.
     */
    peer * const getPeer() const { return _peer; }

    /** alter the stored peer pointer.
     * Perform appropriate CBDATA operations for locking the peer pointer
     */
    void setPeer(peer * p);

private:
    /** cache_peer data object (if any) */
    peer *_peer;
};

}; // namespace Comm

#endif
