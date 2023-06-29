/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

#ifndef _SQUIDCONNECTIONDETAIL_H_
#define _SQUIDCONNECTIONDETAIL_H_

#include "base/CodeContext.h"
#include "base/InstanceId.h"
#include "comm/forward.h"
#include "defines.h"
#if USE_SQUID_EUI
#include "eui/Eui48.h"
#include "eui/Eui64.h"
#endif
#include "hier_code.h"
#include "ip/Address.h"
#include "ip/forward.h"
#include "mem/forward.h"
#include "time/gadgets.h"

#include <iosfwd>
#include <ostream>

class CachePeer;

namespace Security
{
class NegotiationHistory;
};

namespace Comm
{

/* TODO: make these a struct of boolean flags members in the connection instead of a bitmap.
 * we can't do that until all non-comm code uses Commm::Connection objects to create FD
 * currently there is code still using comm_open() and comm_openex() synchronously!!
 */
#define COMM_UNSET              0x00
#define COMM_NONBLOCKING        0x01  // default flag.
#define COMM_NOCLOEXEC          0x02
#define COMM_REUSEADDR          0x04  // shared FD may be both accept()ing and read()ing
#define COMM_DOBIND             0x08  // requires a bind()
#define COMM_TRANSPARENT        0x10  // arrived via TPROXY
#define COMM_INTERCEPTION       0x20  // arrived via NAT
#define COMM_REUSEPORT          0x40 //< needs SO_REUSEPORT
/// not registered with Comm and not owned by any connection-closing code
#define COMM_ORPHANED           0x80
/// Internal Comm optimization: Keep the source port unassigned until connect(2)
#define COMM_DOBIND_PORT_LATER 0x100

/**
 * Store data about the physical and logical attributes of a connection.
 *
 * Some link state can be inferred from the data, however this is not an
 * object for state data. But a semantic equivalent for FD with easily
 * accessible cached properties not requiring repeated complex lookups.
 *
 * Connection properties may be changed until the connection is opened.
 * Properties should be considered read-only outside of the Comm layer
 * code once the connection is open.
 *
 * These objects should not be passed around directly,
 * but a Comm::ConnectionPointer should be passed instead.
 */
class Connection: public CodeContext
{
    MEMPROXY_CLASS(Comm::Connection);

public:
    Connection();

    /** Clear the connection properties and close any open socket. */
    ~Connection() override;

    /// To prevent accidental copying of Connection objects that we started to
    /// open or that are open, use cloneProfile() instead.
    Connection(const Connection &&) = delete;

    /// Create a new closed Connection with the same configuration as this one.
    ConnectionPointer cloneProfile() const;

    /// close the still-open connection when its last reference is gone
    void enterOrphanage() { flags |= COMM_ORPHANED; }
    /// resume relying on owner(s) to initiate an explicit connection closure
    void leaveOrphanage() { flags &= ~COMM_ORPHANED; }

    /** Close any open socket. */
    void close();

    /** Synchronize with Comm: Somebody closed our connection. */
    void noteClosure();

    /** determine whether this object describes an active connection or not. */
    bool isOpen() const { return (fd >= 0); }

    /** Alter the stored IP address pair.
     * WARNING: Does not ensure matching IPv4/IPv6 are supplied.
     */
    void setAddrs(const Ip::Address &aLocal, const Ip::Address &aRemote) {local = aLocal; remote = aRemote;}

    /** retrieve the CachePeer pointer for use.
     * The caller is responsible for all CBDATA operations regarding the
     * used of the pointer returned.
     */
    CachePeer * getPeer() const;

    /** alter the stored CachePeer pointer.
     * Perform appropriate CBDATA operations for locking the CachePeer pointer
     */
    void setPeer(CachePeer * p);

    /** The time the connection started */
    time_t startTime() const {return startTime_;}

    /** The connection lifetime */
    time_t lifeTime() const {return squid_curtime - startTime_;}

    /** The time left for this connection*/
    time_t timeLeft(const time_t idleTimeout) const;

    /// Connection establishment timeout for callers that have already decided
    /// to connect(2), either for the first time or after checking
    /// EnoughTimeToReForward() during any re-forwarding attempts.
    /// \returns the time left for this connection to become connected
    /// \param fwdStart The start time of the peer selection/connection process.
    time_t connectTimeout(const time_t fwdStart) const;

    void noteStart() {startTime_ = squid_curtime;}

    Security::NegotiationHistory *tlsNegotiations();
    const Security::NegotiationHistory *hasTlsNegotiations() const {return tlsHistory;}

    /* CodeContext API */
    ScopedId codeContextGist() const override;
    std::ostream &detailCodeContext(std::ostream &os) const override;

public:
    /** Address/Port for the Squid end of a TCP link. */
    Ip::Address local;

    /** Address for the Remote end of a TCP link. */
    Ip::Address remote;

    /** Hierarchy code for this connection link */
    hier_code peerType;

    /** Socket used by this connection. Negative if not open. */
    int fd;

    /** Quality of Service TOS values currently sent on this connection */
    tos_t tos;

    /** Netfilter MARK values currently sent on this connection
     * In case of FTP, the MARK will be sent on data connections as well.
     */
    nfmark_t nfmark;

    /** Netfilter CONNMARK value previously retrieved from this connection
     * In case of FTP, the CONNMARK will NOT be applied to data connections, for one main reason:
     * the CONNMARK could be set by a third party like iptables and overwriting it in squid may
     * cause side effects and break CONNMARK-based policy. In other words, data connection is
     * related to control connection, but it's not the same.
     */
    nfmark_t nfConnmark = 0;

    /** COMM flags set on this connection */
    int flags;

    char rfc931[USER_IDENT_SZ];

#if USE_SQUID_EUI
    Eui::Eui48 remoteEui48;
    Eui::Eui64 remoteEui64;
#endif

    InstanceId<Connection, uint64_t> id;

private:
    /** cache_peer data object (if any) */
    CachePeer *peer_;

    /** The time the connection object was created */
    time_t startTime_;

    /** TLS connection details*/
    Security::NegotiationHistory *tlsHistory;
};

std::ostream &operator <<(std::ostream &, const Connection &);

inline std::ostream &
operator <<(std::ostream &os, const ConnectionPointer &conn)
{
    if (conn != nullptr)
        os << *conn;
    return os;
}

} // namespace Comm

#endif

