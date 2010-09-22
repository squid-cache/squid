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

#include "config.h"
#include "comm/forward.h"
#include "hier_code.h"
#include "ip/Address.h"
#include "RefCount.h"

#if HAVE_IOSFWD
#include <iosfwd>
#endif
#if HAVE_OSTREAM
#include <ostream>
#endif

struct peer;

namespace Comm {

/* TODO: make these a struct of boolean flags members in the connection instead of a bitmap.
 * we can't do that until all non-comm code uses Commm::Connection objects to create FD
 * currently there is code still using comm_open() and comm_openex() synchronously!!
 */
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
 * While the properties may be changed, this is for teh purpose of creating
 * potential connection descriptors which may be opened. Properties should
 * be considered read-only outside of the Comm layer code once the connection
 * is open.
 *
 * These objects must not be passed around directly,
 * but a Comm::ConnectionPointer must be passed instead.
 */
class Connection : public RefCountable
{
public:
    /** standard empty connection creation */
    Connection();

    /** Clear the connection properties and close any open socket. */
    ~Connection();

    /** Copy an existing connections IP and properties.
     * This excludes the FD. The new copy will be a closed connection.
     */
    ConnectionPointer copyDetails() const;

    /** Close any open socket. */
    void close();

    /** determine whether this object describes an active connection or not. */
    bool isOpen() const { return (fd >= 0); }

    /** retrieve the peer pointer for use.
     * The caller is responsible for all CBDATA operations regarding the
     * used of the pointer returned.
     */
    peer * const getPeer() const;

    /** alter the stored peer pointer.
     * Perform appropriate CBDATA operations for locking the peer pointer
     */
    void setPeer(peer * p);

private:
    /** These objects may not be exactly duplicated. Use copyDetails() instead. */
    Connection(const Connection &c);

    /** These objects may not be exactly duplicated. Use copyDetails() instead. */
    Connection & operator =(const Connection &c);

public:
    /** Address/Port for the Squid end of a TCP link. */
    Ip::Address local;

    /** Address for the Remote end of a TCP link. */
    Ip::Address remote;

    /** Hierarchy code for this connection link */
    hier_code peerType;

    /** Socket used by this connection. -1 if no socket has been opened. */
    int fd;

    /** Quality of Service TOS values currently sent on this connection */
    int tos;

    /** COMM flags set on this connection */
    int flags;

private:
    // XXX: we need to call this member peer_ but the struct peer_ global type
    //      behind peer* clashes despite our private Comm:: namespace
    //      (it being global gets inherited here too).

    /** cache_peer data object (if any) */
    peer *_peer;
};

}; // namespace Comm


// NP: Order and namespace here is very important.
//     * The second define inlines the first.
//     * Stream inheritance overloading is searched in the global scope first.

inline std::ostream &
operator << (std::ostream &os, const Comm::Connection &conn)
{
    os << "FD " << conn.fd << " local=" << conn.local <<
        " remote=" << conn.remote << " flags=" << conn.flags;
    return os;
}

inline std::ostream &
operator << (std::ostream &os, const Comm::ConnectionPointer &conn)
{
    if (conn != NULL)
        os << *conn;
    return os;
}

#endif
