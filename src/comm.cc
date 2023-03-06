/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

#include "squid.h"
#include "base/AsyncFunCalls.h"
#include "ClientInfo.h"
#include "comm/AcceptLimiter.h"
#include "comm/comm_internal.h"
#include "comm/Connection.h"
#include "comm/IoCallback.h"
#include "comm/Loops.h"
#include "comm/Read.h"
#include "comm/TcpAcceptor.h"
#include "comm/Write.h"
#include "compat/cmsg.h"
#include "DescriptorSet.h"
#include "event.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "icmp/net_db.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "pconn.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "StoreIOBuffer.h"
#include "tools.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <cerrno>
#include <cmath>
#if _SQUID_CYGWIN_
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

/*
 * New C-like simple comm code. This stuff is a mess and doesn't really buy us anything.
 */

static IOCB commHalfClosedReader;
static int comm_openex(int sock_type, int proto, Ip::Address &, int flags, const char *note);
static void comm_init_opened(const Comm::ConnectionPointer &conn, const char *note, struct addrinfo *AI);
static int comm_apply_flags(int new_socket, Ip::Address &addr, int flags, struct addrinfo *AI);

#if USE_DELAY_POOLS
CBDATA_CLASS_INIT(CommQuotaQueue);

static void commHandleWriteHelper(void * data);
#endif

/* STATIC */

static DescriptorSet *TheHalfClosed = nullptr; /// the set of half-closed FDs
static bool WillCheckHalfClosed = false; /// true if check is scheduled
static EVH commHalfClosedCheck;
static void commPlanHalfClosedCheck();

static Comm::Flag commBind(int s, struct addrinfo &);
static void commSetBindAddressNoPort(int);
static void commSetReuseAddr(int);
static void commSetNoLinger(int);
#ifdef TCP_NODELAY
static void commSetTcpNoDelay(int);
#endif
static void commSetTcpRcvbuf(int, int);

bool
isOpen(const int fd)
{
    return fd >= 0 && fd_table && fd_table[fd].flags.open != 0;
}

/**
 * Empty the read buffers
 *
 * This is a magical routine that empties the read buffers.
 * Under some platforms (Linux) if a buffer has data in it before
 * you call close(), the socket will hang and take quite a while
 * to timeout.
 */
static void
comm_empty_os_read_buffers(int fd)
{
#if _SQUID_LINUX_
#if USE_OPENSSL
    // Bug 4146: SSL-Bump BIO does not release sockets on close.
    if (fd_table[fd].ssl)
        return;
#endif

    /* prevent those nasty RST packets */
    char buf[SQUID_TCP_SO_RCVBUF];
    if (fd_table[fd].flags.nonblocking && fd_table[fd].type != FD_MSGHDR) {
        while (FD_READ_METHOD(fd, buf, SQUID_TCP_SO_RCVBUF) > 0) {};
    }
#else
    (void)fd;
#endif
}

/**
 * synchronous wrapper around udp socket functions
 */
int
comm_udp_recvfrom(int fd, void *buf, size_t len, int flags, Ip::Address &from)
{
    ++ statCounter.syscalls.sock.recvfroms;
    debugs(5,8, "comm_udp_recvfrom: FD " << fd << " from " << from);
    struct addrinfo *AI = nullptr;
    Ip::Address::InitAddr(AI);
    int x = recvfrom(fd, buf, len, flags, AI->ai_addr, &AI->ai_addrlen);
    from = *AI;
    Ip::Address::FreeAddr(AI);
    return x;
}

int
comm_udp_recv(int fd, void *buf, size_t len, int flags)
{
    Ip::Address nul;
    return comm_udp_recvfrom(fd, buf, len, flags, nul);
}

ssize_t
comm_udp_send(int s, const void *buf, size_t len, int flags)
{
    return send(s, buf, len, flags);
}

bool
comm_has_incomplete_write(int fd)
{
    assert(isOpen(fd) && COMMIO_FD_WRITECB(fd) != nullptr);
    return COMMIO_FD_WRITECB(fd)->active();
}

/**
 * Queue a write. handler/handler_data are called when the write fully
 * completes, on error, or on file descriptor close.
 */

/* Return the local port associated with fd. */
unsigned short
comm_local_port(int fd)
{
    Ip::Address temp;
    struct addrinfo *addr = nullptr;
    fde *F = &fd_table[fd];

    /* If the fd is closed already, just return */

    if (!F->flags.open) {
        debugs(5, 0, "comm_local_port: FD " << fd << " has been closed.");
        return 0;
    }

    if (F->local_addr.port())
        return F->local_addr.port();

    if (F->sock_family == AF_INET)
        temp.setIPv4();

    Ip::Address::InitAddr(addr);

    if (getsockname(fd, addr->ai_addr, &(addr->ai_addrlen)) ) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: " << MYNAME << "Failed to retrieve TCP/UDP port number for socket: FD " << fd << ": " << xstrerr(xerrno));
        Ip::Address::FreeAddr(addr);
        return 0;
    }
    temp = *addr;

    Ip::Address::FreeAddr(addr);

    if (F->local_addr.isAnyAddr()) {
        /* save the whole local address, not just the port. */
        F->local_addr = temp;
    } else {
        F->local_addr.port(temp.port());
    }

    debugs(5, 6, "comm_local_port: FD " << fd << ": port " << F->local_addr.port() << "(family=" << F->sock_family << ")");
    return F->local_addr.port();
}

/// sets the IP_BIND_ADDRESS_NO_PORT socket option to optimize ephemeral port
/// reuse by outgoing TCP connections that must bind(2) to a source IP address
static void
commSetBindAddressNoPort(const int fd)
{
#if defined(IP_BIND_ADDRESS_NO_PORT)
    int flag = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, reinterpret_cast<char*>(&flag), sizeof(flag)) < 0) {
        const auto savedErrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: setsockopt(IP_BIND_ADDRESS_NO_PORT) failure: " << xstrerr(savedErrno));
    }
#else
    (void)fd;
#endif
}

static Comm::Flag
commBind(int s, struct addrinfo &inaddr)
{
    ++ statCounter.syscalls.sock.binds;

    if (bind(s, inaddr.ai_addr, inaddr.ai_addrlen) == 0) {
        debugs(50, 6, "bind socket FD " << s << " to " << fd_table[s].local_addr);
        return Comm::OK;
    }
    int xerrno = errno;
    debugs(50, DBG_CRITICAL, "ERROR: " << MYNAME << "Cannot bind socket FD " << s << " to " << fd_table[s].local_addr << ": " << xstrerr(xerrno));

    return Comm::COMM_ERROR;
}

/**
 * Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in comm.h. Defaults TOS
 */
int
comm_open(int sock_type,
          int proto,
          Ip::Address &addr,
          int flags,
          const char *note)
{
    // assume zero-port callers do not need to know the assigned port right away
    if (sock_type == SOCK_STREAM && addr.port() == 0 && ((flags & COMM_DOBIND) || !addr.isAnyAddr()))
        flags |= COMM_DOBIND_PORT_LATER;

    return comm_openex(sock_type, proto, addr, flags, note);
}

void
comm_open_listener(int sock_type,
                   int proto,
                   Comm::ConnectionPointer &conn,
                   const char *note)
{
    /* all listener sockets require bind() */
    conn->flags |= COMM_DOBIND;

    /* attempt native enabled port. */
    conn->fd = comm_openex(sock_type, proto, conn->local, conn->flags, note);
}

int
comm_open_listener(int sock_type,
                   int proto,
                   Ip::Address &addr,
                   int flags,
                   const char *note)
{
    int sock = -1;

    /* all listener sockets require bind() */
    flags |= COMM_DOBIND;

    /* attempt native enabled port. */
    sock = comm_openex(sock_type, proto, addr, flags, note);

    return sock;
}

static bool
limitError(int const anErrno)
{
    return anErrno == ENFILE || anErrno == EMFILE;
}

static void
comm_set_v6only(int fd, int tos)
{
#ifdef IPV6_V6ONLY
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &tos, sizeof(int)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "setsockopt(IPV6_V6ONLY) " << (tos?"ON":"OFF") << " for FD " << fd << ": " << xstrerr(xerrno));
    }
#else
    debugs(50, DBG_CRITICAL, MYNAME << "WARNING: setsockopt(IPV6_V6ONLY) not supported on this platform");
#endif /* sockopt */
}

/**
 * Set the socket option required for TPROXY spoofing for:
 * - Linux TPROXY v4 support,
 * - OpenBSD divert-to support,
 * - FreeBSD IPFW TPROXY v4 support.
 */
static void
comm_set_transparent(int fd)
{
#if _SQUID_LINUX_ && defined(IP_TRANSPARENT) // Linux
# define soLevel SOL_IP
# define soFlag  IP_TRANSPARENT
    bool doneSuid = false;

#elif defined(SO_BINDANY) // OpenBSD 4.7+ and NetBSD with PF
# define soLevel SOL_SOCKET
# define soFlag  SO_BINDANY
    enter_suid();
    bool doneSuid = true;

#elif defined(IP_BINDANY) // FreeBSD with IPFW
# define soLevel IPPROTO_IP
# define soFlag  IP_BINDANY
    enter_suid();
    bool doneSuid = true;

#else
    debugs(50, DBG_CRITICAL, "WARNING: comm_open: setsockopt(TPROXY) not supported on this platform");
    (void)fd;
#endif /* sockopt */

#if defined(soLevel) && defined(soFlag)
    int tos = 1;
    if (setsockopt(fd, soLevel, soFlag, (char *) &tos, sizeof(int)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "setsockopt(TPROXY) on FD " << fd << ": " << xstrerr(xerrno));
    } else {
        /* mark the socket as having transparent options */
        fd_table[fd].flags.transparent = true;
    }
    if (doneSuid)
        leave_suid();
#endif
}

/**
 * Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in defines.h:COMM_*
 */
static int
comm_openex(int sock_type,
            int proto,
            Ip::Address &addr,
            int flags,
            const char *note)
{
    int new_socket;
    struct addrinfo *AI = nullptr;

    /* Create socket for accepting new connections. */
    ++ statCounter.syscalls.sock.sockets;

    if (!Ip::EnableIpv6 && addr.isIPv6()) {
        debugs(50, 2, "refusing to open an IPv6 socket when IPv6 support is disabled: " << addr);
        errno = ENOTSUP;
        return -1;
    }

    /* Setup the socket addrinfo details for use */
    addr.getAddrInfo(AI);
    AI->ai_socktype = sock_type;
    AI->ai_protocol = proto;

    debugs(50, 3, "comm_openex: Attempt open socket for: " << addr );

    new_socket = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);
    const auto firstErrNo = errno;

    /* under IPv6 there is the possibility IPv6 is present but disabled. */
    /* try again as IPv4-native if possible */
    if ( new_socket < 0 && Ip::EnableIpv6 && addr.isIPv6() && addr.setIPv4() ) {
        /* attempt to open this IPv4-only. */
        Ip::Address::FreeAddr(AI);
        /* Setup the socket addrinfo details for use */
        addr.getAddrInfo(AI);
        AI->ai_socktype = sock_type;
        AI->ai_protocol = proto;
        debugs(50, 3, "Attempt fallback open socket for: " << addr );
        new_socket = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);
        // TODO: Report failures of this second socket() call.
        // if both socket() calls fail, we use firstErrNo
        debugs(50, 2, "attempt open " << note << " socket on: " << addr);
    }

    if (new_socket < 0) {
        /* Increase the number of reserved fd's if calls to socket()
         * are failing because the open file table is full.  This
         * limits the number of simultaneous clients */

        if (limitError(firstErrNo)) {
            debugs(50, DBG_IMPORTANT, MYNAME << "socket failure: " << xstrerr(firstErrNo));
            fdAdjustReserved();
        } else {
            debugs(50, DBG_CRITICAL, MYNAME << "socket failure: " << xstrerr(firstErrNo));
        }

        Ip::Address::FreeAddr(AI);

        errno = firstErrNo; // restore for caller
        return -1;
    }

    // XXX: temporary for the transition. comm_openex will eventually have a conn to play with.
    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->local = addr;
    conn->fd = new_socket;

    debugs(50, 3, "comm_openex: Opened socket " << conn << " : family=" << AI->ai_family << ", type=" << AI->ai_socktype << ", protocol=" << AI->ai_protocol );

    if ( Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && addr.isIPv6() )
        comm_set_v6only(conn->fd, 1);

    /* Windows Vista supports Dual-Sockets. BUT defaults them to V6ONLY. Turn it OFF. */
    /* Other OS may have this administratively disabled for general use. Same deal. */
    if ( Ip::EnableIpv6&IPV6_SPECIAL_V4MAPPING && addr.isIPv6() )
        comm_set_v6only(conn->fd, 0);

    comm_init_opened(conn, note, AI);
    new_socket = comm_apply_flags(conn->fd, addr, flags, AI);

    Ip::Address::FreeAddr(AI);

    // XXX transition only. prevent conn from closing the new FD on function exit.
    conn->fd = -1;
    // XXX: firstErrNo is not applicable here -- socket() calls succeeded above!
    // TODO: Stop reporting error codes via errno.
    errno = firstErrNo;
    return new_socket;
}

/// update FD tables after a local or remote (IPC) comm_openex();
void
comm_init_opened(const Comm::ConnectionPointer &conn,
                 const char *note,
                 struct addrinfo *AI)
{
    assert(Comm::IsConnOpen(conn));
    assert(AI);

    /* update fdstat */
    debugs(5, 5, conn << " is a new socket");

    assert(!isOpen(conn->fd)); // NP: global isOpen checks the fde entry for openness not the Comm::Connection
    fd_open(conn->fd, FD_SOCKET, note);

    fde *F = &fd_table[conn->fd];
    F->local_addr = conn->local;

    F->sock_family = AI->ai_family;
}

/// apply flags after a local comm_open*() call;
/// returns new_socket or -1 on error
static int
comm_apply_flags(int new_socket,
                 Ip::Address &addr,
                 int flags,
                 struct addrinfo *AI)
{
    assert(new_socket >= 0);
    assert(AI);
    const int sock_type = AI->ai_socktype;

    if (!(flags & COMM_NOCLOEXEC))
        commSetCloseOnExec(new_socket);

    if ((flags & COMM_REUSEADDR))
        commSetReuseAddr(new_socket);

    if (addr.port() > (unsigned short) 0) {
#if _SQUID_WINDOWS_
        if (sock_type != SOCK_DGRAM)
#endif
            commSetNoLinger(new_socket);

        if (opt_reuseaddr)
            commSetReuseAddr(new_socket);
    }

    /* MUST be done before binding or face OS Error: "(99) Cannot assign requested address"... */
    if ((flags & COMM_TRANSPARENT)) {
        comm_set_transparent(new_socket);
    }

    if ( (flags & COMM_DOBIND) || addr.port() > 0 || !addr.isAnyAddr() ) {
        if ( !(flags & COMM_DOBIND) && addr.isAnyAddr() )
            debugs(5, DBG_IMPORTANT,"WARNING: Squid is attempting to bind() port " << addr << " without being a listener.");
        if ( addr.isNoAddr() )
            debugs(5, DBG_CRITICAL, "ERROR: Squid is attempting to bind() port " << addr << "!!");

#if defined(SO_REUSEPORT)
        if (flags & COMM_REUSEPORT) {
            int on = 1;
            if (setsockopt(new_socket, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<char*>(&on), sizeof(on)) < 0) {
                const auto savedErrno = errno;
                const auto errorMessage = ToSBuf("cannot enable SO_REUSEPORT socket option when binding to ",
                                                 addr, ": ", xstrerr(savedErrno));
                if (reconfiguring)
                    debugs(5, DBG_IMPORTANT, "ERROR: " << errorMessage);
                else
                    throw TexcHere(errorMessage);
            }
        }
#endif

        if ((flags & COMM_DOBIND_PORT_LATER))
            commSetBindAddressNoPort(new_socket);

        if (commBind(new_socket, *AI) != Comm::OK) {
            comm_close(new_socket);
            return -1;
        }
    }

    if (flags & COMM_NONBLOCKING)
        if (commSetNonBlocking(new_socket) == Comm::COMM_ERROR) {
            comm_close(new_socket);
            return -1;
        }

#ifdef TCP_NODELAY
    if (sock_type == SOCK_STREAM)
        commSetTcpNoDelay(new_socket);

#endif

    if (Config.tcpRcvBufsz > 0 && sock_type == SOCK_STREAM)
        commSetTcpRcvbuf(new_socket, Config.tcpRcvBufsz);

    return new_socket;
}

void
comm_import_opened(const Comm::ConnectionPointer &conn,
                   const char *note,
                   struct addrinfo *AI)
{
    debugs(5, 2, conn);
    assert(Comm::IsConnOpen(conn));
    assert(AI);

    comm_init_opened(conn, note, AI);

    if (!(conn->flags & COMM_NOCLOEXEC))
        fd_table[conn->fd].flags.close_on_exec = true;

    if (conn->local.port() > (unsigned short) 0) {
#if _SQUID_WINDOWS_
        if (AI->ai_socktype != SOCK_DGRAM)
#endif
            fd_table[conn->fd].flags.nolinger = true;
    }

    if ((conn->flags & COMM_TRANSPARENT))
        fd_table[conn->fd].flags.transparent = true;

    if (conn->flags & COMM_NONBLOCKING)
        fd_table[conn->fd].flags.nonblocking = true;

#ifdef TCP_NODELAY
    if (AI->ai_socktype == SOCK_STREAM)
        fd_table[conn->fd].flags.nodelay = true;
#endif

    /* no fd_table[fd].flags. updates needed for these conditions:
     * if ((flags & COMM_REUSEADDR)) ...
     * if ((flags & COMM_DOBIND) ...) ...
     */
}

// XXX: now that raw-FD timeouts are only unset for pipes and files this SHOULD be a no-op.
// With handler already unset. Leaving this present until that can be verified for all code paths.
void
commUnsetFdTimeout(int fd)
{
    debugs(5, 3, "Remove timeout for FD " << fd);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);
    fde *F = &fd_table[fd];
    assert(F->flags.open);

    F->timeoutHandler = nullptr;
    F->timeout = 0;
}

int
commSetConnTimeout(const Comm::ConnectionPointer &conn, int timeout, AsyncCall::Pointer &callback)
{
    debugs(5, 3, conn << " timeout " << timeout);
    assert(Comm::IsConnOpen(conn));
    assert(conn->fd < Squid_MaxFD);
    fde *F = &fd_table[conn->fd];
    assert(F->flags.open);

    if (timeout < 0) {
        F->timeoutHandler = nullptr;
        F->timeout = 0;
    } else {
        if (callback != nullptr) {
            typedef CommTimeoutCbParams Params;
            Params &params = GetCommParams<Params>(callback);
            params.conn = conn;
            F->timeoutHandler = callback;
        }

        F->timeout = squid_curtime + (time_t) timeout;
    }

    return F->timeout;
}

int
commUnsetConnTimeout(const Comm::ConnectionPointer &conn)
{
    debugs(5, 3, "Remove timeout for " << conn);
    AsyncCall::Pointer nil;
    return commSetConnTimeout(conn, -1, nil);
}

/**
 * Connect socket FD to given remote address.
 * If return value is an error flag (COMM_ERROR, ERR_CONNECT, ERR_PROTOCOL, etc.),
 * then error code will also be returned in errno.
 */
int
comm_connect_addr(int sock, const Ip::Address &address)
{
    Comm::Flag status = Comm::OK;
    fde *F = &fd_table[sock];
    int x = 0;
    int err = 0;
    socklen_t errlen;
    struct addrinfo *AI = nullptr;

    assert(address.port() != 0);

    debugs(5, 9, "connecting socket FD " << sock << " to " << address << " (want family: " << F->sock_family << ")");

    /* Handle IPv6 over IPv4-only socket case.
     * this case must presently be handled here since the getAddrInfo asserts on bad mappings.
     * NP: because commResetFD is private to ConnStateData we have to return an error and
     *     trust its handled properly.
     */
    if (F->sock_family == AF_INET && !address.isIPv4()) {
        errno = ENETUNREACH;
        return Comm::ERR_PROTOCOL;
    }

    /* Handle IPv4 over IPv6-only socket case.
     * This case is presently handled here as it's both a known case and it's
     * uncertain what error will be returned by the IPv6 stack in such case. It's
     * possible this will also be handled by the errno checks below after connect()
     * but needs careful cross-platform verification, and verifying the address
     * condition here is simple.
     */
    if (!F->local_addr.isIPv4() && address.isIPv4()) {
        errno = ENETUNREACH;
        return Comm::ERR_PROTOCOL;
    }

    address.getAddrInfo(AI, F->sock_family);

    /* Establish connection. */
    int xerrno = 0;

    if (!F->flags.called_connect) {
        F->flags.called_connect = true;
        ++ statCounter.syscalls.sock.connects;

        errno = 0;
        if ((x = connect(sock, AI->ai_addr, AI->ai_addrlen)) < 0) {
            xerrno = errno;
            debugs(5,5, "sock=" << sock << ", addrinfo(" <<
                   " flags=" << AI->ai_flags <<
                   ", family=" << AI->ai_family <<
                   ", socktype=" << AI->ai_socktype <<
                   ", protocol=" << AI->ai_protocol <<
                   ", &addr=" << AI->ai_addr <<
                   ", addrlen=" << AI->ai_addrlen << " )");
            debugs(5, 9, "connect FD " << sock << ": (" << x << ") " << xstrerr(xerrno));
            debugs(14,9, "connecting to: " << address);

        } else if (x == 0) {
            // XXX: ICAP code refuses callbacks during a pending comm_ call
            // Async calls development will fix this.
            x = -1;
            xerrno = EINPROGRESS;
        }

    } else {
        errno = 0;
#if _SQUID_NEWSOS6_
        /* Makoto MATSUSHITA <matusita@ics.es.osaka-u.ac.jp> */
        if (connect(sock, AI->ai_addr, AI->ai_addrlen) < 0)
            xerrno = errno;

        if (xerrno == EINVAL) {
            errlen = sizeof(err);
            x = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
            if (x >= 0)
                xerrno = x;
        }
#else
        errlen = sizeof(err);
        x = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (x == 0)
            xerrno = err;

#if _SQUID_SOLARIS_
        /*
        * Solaris 2.4's socket emulation doesn't allow you
        * to determine the error from a failed non-blocking
        * connect and just returns EPIPE.  Create a fake
        * error message for connect.   -- fenner@parc.xerox.com
        */
        if (x < 0 && xerrno == EPIPE)
            xerrno = ENOTCONN;
        else
            xerrno = errno;
#endif
#endif
    }

    Ip::Address::FreeAddr(AI);

    errno = xerrno;
    if (xerrno == 0 || xerrno == EISCONN)
        status = Comm::OK;
    else if (ignoreErrno(xerrno))
        status = Comm::INPROGRESS;
    else if (xerrno == EAFNOSUPPORT || xerrno == EINVAL)
        return Comm::ERR_PROTOCOL;
    else
        return Comm::COMM_ERROR;

    address.toStr(F->ipaddr, MAX_IPSTRLEN);

    F->remote_port = address.port(); /* remote_port is HS */

    if (status == Comm::OK) {
        debugs(5, DBG_DATA, "comm_connect_addr: FD " << sock << " connected to " << address);
    } else if (status == Comm::INPROGRESS) {
        debugs(5, DBG_DATA, "comm_connect_addr: FD " << sock << " connection pending");
    }

    errno = xerrno;
    return status;
}

void
commCallCloseHandlers(int fd)
{
    fde *F = &fd_table[fd];
    debugs(5, 5, "commCallCloseHandlers: FD " << fd);

    while (F->closeHandler != nullptr) {
        AsyncCall::Pointer call = F->closeHandler;
        F->closeHandler = call->Next();
        call->setNext(nullptr);
        // If call is not canceled schedule it for execution else ignore it
        if (!call->canceled()) {
            debugs(5, 5, "commCallCloseHandlers: ch->handler=" << call);
            // XXX: Without the following code, callback fd may be -1.
            // typedef CommCloseCbParams Params;
            // auto &params = GetCommParams<Params>(call);
            // params.fd = fd;
            ScheduleCallHere(call);
        }
    }
}

/**
 * enable linger with time of 0 so that when the socket is
 * closed, TCP generates a RESET
 */
void
comm_reset_close(const Comm::ConnectionPointer &conn)
{
    struct linger L;
    L.l_onoff = 1;
    L.l_linger = 0;

    if (setsockopt(conn->fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "ERROR: Closing " << conn << " with TCP RST: " << xstrerr(xerrno));
    }
    conn->close();
}

// Legacy close function.
void
old_comm_reset_close(int fd)
{
    struct linger L;
    L.l_onoff = 1;
    L.l_linger = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "ERROR: Closing FD " << fd << " with TCP RST: " << xstrerr(xerrno));
    }
    comm_close(fd);
}

static void
commStartTlsClose(const int fd)
{
    Security::SessionSendGoodbye(fd_table[fd].ssl);
}

static void
comm_close_complete(const int fd)
{
    auto F = &fd_table[fd];
    F->ssl.reset();
    F->dynamicTlsContext.reset();
    fd_close(fd); /* update fdstat */
    close(fd);

    ++ statCounter.syscalls.sock.closes;

    /* When one connection closes, give accept() a chance, if need be */
    CodeContext::Reset(); // exit FD-specific context
    Comm::AcceptLimiter::Instance().kick();
}

/*
 * Close the socket fd.
 *
 * + call write handlers with ERR_CLOSING
 * + call read handlers with ERR_CLOSING
 * + call closing handlers
 *
 * A deferred reader has no Comm read handler mentioned above. To stay in sync,
 * such a reader must register a Comm closing handler.
 */
void
_comm_close(int fd, char const *file, int line)
{
    debugs(5, 3, "start closing FD " << fd << " by " << file << ":" << line);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);

    fde *F = &fd_table[fd];

    if (F->closing())
        return;

    /* XXX: is this obsolete behind F->closing() ? */
    if ( (shutting_down || reconfiguring) && (!F->flags.open || F->type == FD_FILE))
        return;

    /* The following fails because ipc.c is doing calls to pipe() to create sockets! */
    if (!isOpen(fd)) {
        debugs(50, DBG_IMPORTANT, "ERROR: Squid BUG #3556: FD " << fd << " is not an open socket.");
        // XXX: do we need to run close(fd) or fd_close(fd) here?
        return;
    }

    assert(F->type != FD_FILE);

    F->flags.close_request = true;

    // We have caller's context and fde::codeContext. In the unlikely event they
    // differ, it is not clear which context is more applicable to this closure.
    // For simplicity sake, we remain in the caller's context while still
    // allowing individual advanced callbacks to overwrite it.

    if (F->ssl) {
        const auto startCall = asyncCall(5, 4, "commStartTlsClose",
                                         callDialer(commStartTlsClose, fd));
        ScheduleCallHere(startCall);
    }

    // a half-closed fd may lack a reader, so we stop monitoring explicitly
    if (commHasHalfClosedMonitor(fd))
        commStopHalfClosedMonitor(fd);
    commUnsetFdTimeout(fd);

    // notify read/write handlers after canceling select reservations, if any
    if (COMMIO_FD_WRITECB(fd)->active()) {
        Comm::SetSelect(fd, COMM_SELECT_WRITE, nullptr, nullptr, 0);
        COMMIO_FD_WRITECB(fd)->finish(Comm::ERR_CLOSING, 0);
    }
    if (COMMIO_FD_READCB(fd)->active()) {
        Comm::SetSelect(fd, COMM_SELECT_READ, nullptr, nullptr, 0);
        COMMIO_FD_READCB(fd)->finish(Comm::ERR_CLOSING, 0);
    }

#if USE_DELAY_POOLS
    if (BandwidthBucket *bucket = BandwidthBucket::SelectBucket(F)) {
        if (bucket->selectWaiting)
            bucket->onFdClosed();
    }
#endif

    commCallCloseHandlers(fd);

    comm_empty_os_read_buffers(fd);

    // must use async call to wait for all callbacks
    // scheduled before comm_close() to finish
    const auto completeCall = asyncCall(5, 4, "comm_close_complete",
                                        callDialer(comm_close_complete, fd));
    ScheduleCallHere(completeCall);
}

/* Send a udp datagram to specified TO_ADDR. */
int
comm_udp_sendto(int fd,
                const Ip::Address &to_addr,
                const void *buf,
                int len)
{
    ++ statCounter.syscalls.sock.sendtos;

    debugs(50, 3, "comm_udp_sendto: Attempt to send UDP packet to " << to_addr <<
           " using FD " << fd << " using Port " << comm_local_port(fd) );

    struct addrinfo *AI = nullptr;
    to_addr.getAddrInfo(AI, fd_table[fd].sock_family);
    int x = sendto(fd, buf, len, 0, AI->ai_addr, AI->ai_addrlen);
    int xerrno = errno;
    Ip::Address::FreeAddr(AI);

    if (x >= 0) {
        errno = xerrno; // restore for caller to use
        return x;
    }

#if _SQUID_LINUX_
    if (ECONNREFUSED != xerrno)
#endif
        debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << ", (family=" << fd_table[fd].sock_family << ") " << to_addr << ": " << xstrerr(xerrno));

    errno = xerrno; // restore for caller to use
    return Comm::COMM_ERROR;
}

AsyncCall::Pointer
comm_add_close_handler(int fd, CLCB * handler, void *data)
{
    debugs(5, 5, "comm_add_close_handler: FD " << fd << ", handler=" <<
           handler << ", data=" << data);

    AsyncCall::Pointer call=commCbCall(5,4, "SomeCloseHandler",
                                       CommCloseCbPtrFun(handler, data));
    comm_add_close_handler(fd, call);
    return call;
}

void
comm_add_close_handler(int fd, AsyncCall::Pointer &call)
{
    debugs(5, 5, "comm_add_close_handler: FD " << fd << ", AsyncCall=" << call);

    /*TODO:Check for a similar scheduled AsyncCall*/
//    for (c = fd_table[fd].closeHandler; c; c = c->next)
//        assert(c->handler != handler || c->data != data);

    // TODO: Consider enhancing AsyncCallList to support random-access close
    // handlers, perhaps after upgrading the remaining legacy CLCB handlers.
    call->setNext(fd_table[fd].closeHandler);

    fd_table[fd].closeHandler = call;
}

// remove function-based close handler
void
comm_remove_close_handler(int fd, CLCB * handler, void *data)
{
    assert(isOpen(fd));
    /* Find handler in list */
    debugs(5, 5, "comm_remove_close_handler: FD " << fd << ", handler=" <<
           handler << ", data=" << data);

    AsyncCall::Pointer p, prev = nullptr;
    for (p = fd_table[fd].closeHandler; p != nullptr; prev = p, p = p->Next()) {
        typedef CommCbFunPtrCallT<CommCloseCbPtrFun> Call;
        const Call *call = dynamic_cast<const Call*>(p.getRaw());
        if (!call) // method callbacks have their own comm_remove_close_handler
            continue;

        typedef CommCloseCbParams Params;
        const Params &params = GetCommParams<Params>(p);
        if (call->dialer.handler == handler && params.data == data)
            break;      /* This is our handler */
    }

    // comm_close removes all close handlers so our handler may be gone
    if (p != nullptr) {
        p->dequeue(fd_table[fd].closeHandler, prev);
        p->cancel("comm_remove_close_handler");
    }
}

// remove method-based close handler
void
comm_remove_close_handler(int fd, AsyncCall::Pointer &call)
{
    assert(isOpen(fd));
    debugs(5, 5, "comm_remove_close_handler: FD " << fd << ", AsyncCall=" << call);

    // comm_close removes all close handlers so our handler may be gone
    AsyncCall::Pointer p, prev = nullptr;
    for (p = fd_table[fd].closeHandler; p != nullptr && p != call; prev = p, p = p->Next());

    if (p != nullptr)
        p->dequeue(fd_table[fd].closeHandler, prev);
    call->cancel("comm_remove_close_handler");
}

static void
commSetNoLinger(int fd)
{

    struct linger L;
    L.l_onoff = 0;      /* off */
    L.l_linger = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
    }
    fd_table[fd].flags.nolinger = true;
}

static void
commSetReuseAddr(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
    }
}

static void
commSetTcpRcvbuf(int fd, int size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << ", SIZE " << size << ": " << xstrerr(xerrno));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &size, sizeof(size)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << ", SIZE " << size << ": " << xstrerr(xerrno));
    }
#ifdef TCP_WINDOW_CLAMP
    if (setsockopt(fd, SOL_TCP, TCP_WINDOW_CLAMP, (char *) &size, sizeof(size)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << ", SIZE " << size << ": " << xstrerr(xerrno));
    }
#endif
}

int
commSetNonBlocking(int fd)
{
#if _SQUID_WINDOWS_
    int nonblocking = TRUE;

    if (ioctl(fd, FIONBIO, &nonblocking) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": " << xstrerr(xerrno) << " " << fd_table[fd].type);
        return Comm::COMM_ERROR;
    }

#else
    int flags;
    int dummy = 0;

    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": fcntl F_GETFL: " << xstrerr(xerrno));
        return Comm::COMM_ERROR;
    }

    if (fcntl(fd, F_SETFL, flags | SQUID_NONBLOCK) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
        return Comm::COMM_ERROR;
    }
#endif

    fd_table[fd].flags.nonblocking = true;
    return 0;
}

int
commUnsetNonBlocking(int fd)
{
#if _SQUID_WINDOWS_
    int nonblocking = FALSE;

    if (ioctlsocket(fd, FIONBIO, (unsigned long *) &nonblocking) < 0) {
#else
    int flags;
    int dummy = 0;

    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": fcntl F_GETFL: " << xstrerr(xerrno));
        return Comm::COMM_ERROR;
    }

    if (fcntl(fd, F_SETFL, flags & (~SQUID_NONBLOCK)) < 0) {
#endif
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
        return Comm::COMM_ERROR;
    }

    fd_table[fd].flags.nonblocking = false;
    return 0;
}

void
commSetCloseOnExec(int fd)
{
#ifdef FD_CLOEXEC
    int flags;
    int dummy = 0;

    if ((flags = fcntl(fd, F_GETFD, dummy)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << "FD " << fd << ": fcntl F_GETFD: " << xstrerr(xerrno));
        return;
    }

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "ERROR: " << MYNAME << "FD " << fd << ": set close-on-exec failed: " << xstrerr(xerrno));
    }

    fd_table[fd].flags.close_on_exec = true;

#endif
}

#ifdef TCP_NODELAY
static void
commSetTcpNoDelay(int fd)
{
    int on = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
    }

    fd_table[fd].flags.nodelay = true;
}

#endif

void
comm_init(void)
{
    assert(fd_table);

    /* make sure the accept() socket FIFO delay queue exists */
    Comm::AcceptLimiter::Instance();

    // make sure the IO pending callback table exists
    Comm::CallbackTableInit();

    /* XXX account fd_table */
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since Squid_MaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = min(100, Squid_MaxFD / 4);

    TheHalfClosed = new DescriptorSet;

    /* setup the select loop module */
    Comm::SelectLoopInit();
}

void
comm_exit(void)
{
    delete TheHalfClosed;
    TheHalfClosed = nullptr;

    Comm::CallbackTableDestruct();
}

#if USE_DELAY_POOLS
// called when the queue is done waiting for the client bucket to fill
void
commHandleWriteHelper(void * data)
{
    CommQuotaQueue *queue = static_cast<CommQuotaQueue*>(data);
    assert(queue);

    ClientInfo *clientInfo = queue->clientInfo;
    // ClientInfo invalidates queue if freed, so if we got here through,
    // evenAdd cbdata protections, everything should be valid and consistent
    assert(clientInfo);
    assert(clientInfo->hasQueue());
    assert(clientInfo->hasQueue(queue));
    assert(clientInfo->eventWaiting);
    clientInfo->eventWaiting = false;

    do {
        clientInfo->writeOrDequeue();
        if (clientInfo->selectWaiting)
            return;
    } while (clientInfo->hasQueue());

    debugs(77, 3, "emptied queue");
}

void
ClientInfo::writeOrDequeue()
{
    assert(!selectWaiting);
    const auto head = quotaPeekFd();
    const auto &headFde = fd_table[head];
    CallBack(headFde.codeContext, [&] {
        const auto ccb = COMMIO_FD_WRITECB(head);
        // check that the head descriptor is still relevant
        if (headFde.clientInfo == this &&
                quotaPeekReserv() == ccb->quotaQueueReserv &&
                !headFde.closing()) {

            // wait for the head descriptor to become ready for writing
            Comm::SetSelect(head, COMM_SELECT_WRITE, Comm::HandleWrite, ccb, 0);
            selectWaiting = true;
        } else {
            quotaDequeue(); // remove the no longer relevant descriptor
        }
    });
}

bool
ClientInfo::hasQueue() const
{
    assert(quotaQueue);
    return !quotaQueue->empty();
}

bool
ClientInfo::hasQueue(const CommQuotaQueue *q) const
{
    assert(quotaQueue);
    return quotaQueue == q;
}

/// returns the first descriptor to be dequeued
int
ClientInfo::quotaPeekFd() const
{
    assert(quotaQueue);
    return quotaQueue->front();
}

/// returns the reservation ID of the first descriptor to be dequeued
unsigned int
ClientInfo::quotaPeekReserv() const
{
    assert(quotaQueue);
    return quotaQueue->outs + 1;
}

/// queues a given fd, creating the queue if necessary; returns reservation ID
unsigned int
ClientInfo::quotaEnqueue(int fd)
{
    assert(quotaQueue);
    return quotaQueue->enqueue(fd);
}

/// removes queue head
void
ClientInfo::quotaDequeue()
{
    assert(quotaQueue);
    quotaQueue->dequeue();
}

void
ClientInfo::kickQuotaQueue()
{
    if (!eventWaiting && !selectWaiting && hasQueue()) {
        // wait at least a second if the bucket is empty
        const double delay = (bucketLevel < 1.0) ? 1.0 : 0.0;
        eventAdd("commHandleWriteHelper", &commHandleWriteHelper,
                 quotaQueue, delay, 0, true);
        eventWaiting = true;
    }
}

/// calculates how much to write for a single dequeued client
int
ClientInfo::quota()
{
    /* If we have multiple clients and give full bucketSize to each client then
     * clt1 may often get a lot more because clt1->clt2 time distance in the
     * select(2) callback order may be a lot smaller than cltN->clt1 distance.
     * We divide quota evenly to be more fair. */

    if (!rationedCount) {
        rationedCount = quotaQueue->size() + 1;

        // The delay in ration recalculation _temporary_ deprives clients from
        // bytes that should have trickled in while rationedCount was positive.
        refillBucket();

        // Rounding errors do not accumulate here, but we round down to avoid
        // negative bucket sizes after write with rationedCount=1.
        rationedQuota = static_cast<int>(floor(bucketLevel/rationedCount));
        debugs(77,5, "new rationedQuota: " << rationedQuota <<
               '*' << rationedCount);
    }

    --rationedCount;
    debugs(77,7, "rationedQuota: " << rationedQuota <<
           " rations remaining: " << rationedCount);

    // update 'last seen' time to prevent clientdb GC from dropping us
    last_seen = squid_curtime;
    return rationedQuota;
}

bool
ClientInfo::applyQuota(int &nleft, Comm::IoCallback *state)
{
    assert(hasQueue());
    assert(quotaPeekFd() == state->conn->fd);
    quotaDequeue(); // we will write or requeue below
    if (nleft > 0 && !BandwidthBucket::applyQuota(nleft, state)) {
        state->quotaQueueReserv = quotaEnqueue(state->conn->fd);
        kickQuotaQueue();
        return false;
    }
    return true;
}

void
ClientInfo::scheduleWrite(Comm::IoCallback *state)
{
    if (writeLimitingActive) {
        state->quotaQueueReserv = quotaEnqueue(state->conn->fd);
        kickQuotaQueue();
    }
}

void
ClientInfo::onFdClosed()
{
    BandwidthBucket::onFdClosed();
    // kick queue or it will get stuck as commWriteHandle is not called
    kickQuotaQueue();
}

void
ClientInfo::reduceBucket(const int len)
{
    if (len > 0)
        BandwidthBucket::reduceBucket(len);
    // even if we wrote nothing, we were served; give others a chance
    kickQuotaQueue();
}

void
ClientInfo::setWriteLimiter(const int aWriteSpeedLimit, const double anInitialBurst, const double aHighWatermark)
{
    debugs(77,5, "Write limits for " << (const char*)key <<
           " speed=" << aWriteSpeedLimit << " burst=" << anInitialBurst <<
           " highwatermark=" << aHighWatermark);

    // set or possibly update traffic shaping parameters
    writeLimitingActive = true;
    writeSpeedLimit = aWriteSpeedLimit;
    bucketSizeLimit = aHighWatermark;

    // but some members should only be set once for a newly activated bucket
    if (firstTimeConnection) {
        firstTimeConnection = false;

        assert(!selectWaiting);
        assert(!quotaQueue);
        quotaQueue = new CommQuotaQueue(this);

        bucketLevel = anInitialBurst;
        prevTime = current_dtime;
    }
}

CommQuotaQueue::CommQuotaQueue(ClientInfo *info): clientInfo(info),
    ins(0), outs(0)
{
    assert(clientInfo);
}

CommQuotaQueue::~CommQuotaQueue()
{
    assert(!clientInfo); // ClientInfo should clear this before destroying us
}

/// places the given fd at the end of the queue; returns reservation ID
unsigned int
CommQuotaQueue::enqueue(int fd)
{
    debugs(77,5, "clt" << (const char*)clientInfo->key <<
           ": FD " << fd << " with qqid" << (ins+1) << ' ' << fds.size());
    fds.push_back(fd);
    fd_table[fd].codeContext = CodeContext::Current();
    return ++ins;
}

/// removes queue head
void
CommQuotaQueue::dequeue()
{
    assert(!fds.empty());
    debugs(77,5, "clt" << (const char*)clientInfo->key <<
           ": FD " << fds.front() << " with qqid" << (outs+1) << ' ' <<
           fds.size());
    fds.pop_front();
    ++outs;
}
#endif /* USE_DELAY_POOLS */

/*
 * hm, this might be too general-purpose for all the places we'd
 * like to use it.
 */
int
ignoreErrno(int ierrno)
{
    switch (ierrno) {

    case EINPROGRESS:

    case EWOULDBLOCK:
#if EAGAIN != EWOULDBLOCK

    case EAGAIN:
#endif

    case EALREADY:

    case EINTR:
#ifdef ERESTART

    case ERESTART:
#endif

        return 1;

    default:
        return 0;
    }

    /* NOTREACHED */
}

void
commCloseAllSockets(void)
{
    int fd;
    fde *F = nullptr;

    for (fd = 0; fd <= Biggest_FD; ++fd) {
        F = &fd_table[fd];

        if (!F->flags.open)
            continue;

        if (F->type != FD_SOCKET)
            continue;

        if (F->flags.ipc)   /* don't close inter-process sockets */
            continue;

        if (F->timeoutHandler != nullptr) {
            AsyncCall::Pointer callback = F->timeoutHandler;
            F->timeoutHandler = nullptr;
            debugs(5, 5, "commCloseAllSockets: FD " << fd << ": Calling timeout handler");
            ScheduleCallHere(callback);
        } else {
            debugs(5, 5, "commCloseAllSockets: FD " << fd << ": calling comm_reset_close()");
            old_comm_reset_close(fd);
        }
    }
}

static bool
AlreadyTimedOut(fde *F)
{
    if (!F->flags.open)
        return true;

    if (F->timeout == 0)
        return true;

    if (F->timeout > squid_curtime)
        return true;

    return false;
}

static bool
writeTimedOut(int fd)
{
    if (!COMMIO_FD_WRITECB(fd)->active())
        return false;

    if ((squid_curtime - fd_table[fd].writeStart) < Config.Timeout.write)
        return false;

    return true;
}

void
checkTimeouts(void)
{
    int fd;
    fde *F = nullptr;
    AsyncCall::Pointer callback;

    for (fd = 0; fd <= Biggest_FD; ++fd) {
        F = &fd_table[fd];

        if (writeTimedOut(fd)) {
            // We have an active write callback and we are timed out
            CodeContext::Reset(F->codeContext);
            debugs(5, 5, "checkTimeouts: FD " << fd << " auto write timeout");
            Comm::SetSelect(fd, COMM_SELECT_WRITE, nullptr, nullptr, 0);
            COMMIO_FD_WRITECB(fd)->finish(Comm::COMM_ERROR, ETIMEDOUT);
            CodeContext::Reset();
            continue;
#if USE_DELAY_POOLS
        } else if (F->writeQuotaHandler != nullptr && COMMIO_FD_WRITECB(fd)->conn != nullptr) {
            // TODO: Move and extract quota() call to place it inside F->codeContext.
            if (!F->writeQuotaHandler->selectWaiting && F->writeQuotaHandler->quota() && !F->closing()) {
                CodeContext::Reset(F->codeContext);
                F->writeQuotaHandler->selectWaiting = true;
                Comm::SetSelect(fd, COMM_SELECT_WRITE, Comm::HandleWrite, COMMIO_FD_WRITECB(fd), 0);
                CodeContext::Reset();
            }
            continue;
#endif
        }
        else if (AlreadyTimedOut(F))
            continue;

        CodeContext::Reset(F->codeContext);
        debugs(5, 5, "checkTimeouts: FD " << fd << " Expired");

        if (F->timeoutHandler != nullptr) {
            debugs(5, 5, "checkTimeouts: FD " << fd << ": Call timeout handler");
            callback = F->timeoutHandler;
            F->timeoutHandler = nullptr;
            ScheduleCallHere(callback);
        } else {
            debugs(5, 5, "checkTimeouts: FD " << fd << ": Forcing comm_close()");
            comm_close(fd);
        }

        CodeContext::Reset();
    }
}

/// Start waiting for a possibly half-closed connection to close
// by scheduling a read callback to a monitoring handler that
// will close the connection on read errors.
void
commStartHalfClosedMonitor(int fd)
{
    debugs(5, 5, "adding FD " << fd << " to " << *TheHalfClosed);
    assert(isOpen(fd) && !commHasHalfClosedMonitor(fd));
    (void)TheHalfClosed->add(fd); // could also assert the result
    fd_table[fd].codeContext = CodeContext::Current();
    commPlanHalfClosedCheck(); // may schedule check if we added the first FD
}

static
void
commPlanHalfClosedCheck()
{
    if (!WillCheckHalfClosed && !TheHalfClosed->empty()) {
        eventAdd("commHalfClosedCheck", &commHalfClosedCheck, nullptr, 1.0, 1);
        WillCheckHalfClosed = true;
    }
}

/// iterates over all descriptors that may need half-closed tests and
/// calls comm_read for those that do; re-schedules the check if needed
static
void
commHalfClosedCheck(void *)
{
    debugs(5, 5, "checking " << *TheHalfClosed);

    typedef DescriptorSet::const_iterator DSCI;
    const DSCI end = TheHalfClosed->end();
    for (DSCI i = TheHalfClosed->begin(); i != end; ++i) {
        Comm::ConnectionPointer c = new Comm::Connection; // XXX: temporary. make HalfClosed a list of these.
        c->fd = *i;
        if (!fd_table[c->fd].halfClosedReader) { // not reading already
            CallBack(fd_table[c->fd].codeContext, [&c] {
                AsyncCall::Pointer call = commCbCall(5,4, "commHalfClosedReader",
                                                     CommIoCbPtrFun(&commHalfClosedReader, nullptr));
                Comm::Read(c, call);
                fd_table[c->fd].halfClosedReader = call;
            });
        } else
            c->fd = -1; // XXX: temporary. prevent c replacement erase closing listed FD
    }

    WillCheckHalfClosed = false; // as far as we know
    commPlanHalfClosedCheck(); // may need to check again
}

/// checks whether we are waiting for possibly half-closed connection to close
// We are monitoring if the read handler for the fd is the monitoring handler.
bool
commHasHalfClosedMonitor(int fd)
{
    return TheHalfClosed->has(fd);
}

/// stop waiting for possibly half-closed connection to close
void
commStopHalfClosedMonitor(int const fd)
{
    debugs(5, 5, "removing FD " << fd << " from " << *TheHalfClosed);

    // cancel the read if one was scheduled
    AsyncCall::Pointer reader = fd_table[fd].halfClosedReader;
    if (reader != nullptr)
        Comm::ReadCancel(fd, reader);
    fd_table[fd].halfClosedReader = nullptr;

    TheHalfClosed->del(fd);
}

/// I/O handler for the possibly half-closed connection monitoring code
static void
commHalfClosedReader(const Comm::ConnectionPointer &conn, char *, size_t size, Comm::Flag flag, int, void *)
{
    // there cannot be more data coming in on half-closed connections
    assert(size == 0);
    assert(conn != nullptr);
    assert(commHasHalfClosedMonitor(conn->fd)); // or we would have canceled the read

    fd_table[conn->fd].halfClosedReader = nullptr; // done reading, for now

    // nothing to do if fd is being closed
    if (flag == Comm::ERR_CLOSING)
        return;

    // if read failed, close the connection
    if (flag != Comm::OK) {
        debugs(5, 3, "closing " << conn);
        conn->close();
        return;
    }

    // continue waiting for close or error
    commPlanHalfClosedCheck(); // make sure this fd will be checked again
}

int
CommSelectEngine::checkEvents(int timeout)
{
    static time_t last_timeout = 0;

    /* No, this shouldn't be here. But it shouldn't be in each comm handler. -adrian */
    if (squid_curtime > last_timeout) {
        last_timeout = squid_curtime;
        checkTimeouts();
    }

    switch (Comm::DoSelect(timeout)) {

    case Comm::OK:

    case Comm::TIMEOUT:
        return 0;

    case Comm::IDLE:

    case Comm::SHUTDOWN:
        return EVENT_IDLE;

    case Comm::COMM_ERROR:
        return EVENT_ERROR;

    default:
        fatal_dump("comm.cc: Internal error -- this should never happen.");
        return EVENT_ERROR;
    };
}

/// Create a unix-domain socket (UDS) that only supports FD_MSGHDR I/O.
int
comm_open_uds(int sock_type,
              int proto,
              struct sockaddr_un* addr,
              int flags)
{
    // TODO: merge with comm_openex() when Ip::Address becomes NetAddress

    int new_socket;

    /* Create socket for accepting new connections. */
    ++ statCounter.syscalls.sock.sockets;

    /* Setup the socket addrinfo details for use */
    struct addrinfo AI;
    AI.ai_flags = 0;
    AI.ai_family = PF_UNIX;
    AI.ai_socktype = sock_type;
    AI.ai_protocol = proto;
    AI.ai_addrlen = SUN_LEN(addr);
    AI.ai_addr = (sockaddr*)addr;
    AI.ai_canonname = nullptr;
    AI.ai_next = nullptr;

    debugs(50, 3, "Attempt open socket for: " << addr->sun_path);

    if ((new_socket = socket(AI.ai_family, AI.ai_socktype, AI.ai_protocol)) < 0) {
        int xerrno = errno;
        /* Increase the number of reserved fd's if calls to socket()
         * are failing because the open file table is full.  This
         * limits the number of simultaneous clients */

        if (limitError(xerrno)) {
            debugs(50, DBG_IMPORTANT, MYNAME << "socket failure: " << xstrerr(xerrno));
            fdAdjustReserved();
        } else {
            debugs(50, DBG_CRITICAL, MYNAME << "socket failure: " << xstrerr(xerrno));
        }
        return -1;
    }

    debugs(50, 3, "Opened UDS FD " << new_socket << " : family=" << AI.ai_family << ", type=" << AI.ai_socktype << ", protocol=" << AI.ai_protocol);

    /* update fdstat */
    debugs(50, 5, "FD " << new_socket << " is a new socket");

    assert(!isOpen(new_socket));
    fd_open(new_socket, FD_MSGHDR, addr->sun_path);

    fd_table[new_socket].sock_family = AI.ai_family;

    if (!(flags & COMM_NOCLOEXEC))
        commSetCloseOnExec(new_socket);

    if (flags & COMM_REUSEADDR)
        commSetReuseAddr(new_socket);

    if (flags & COMM_NONBLOCKING) {
        if (commSetNonBlocking(new_socket) != Comm::OK) {
            comm_close(new_socket);
            return -1;
        }
    }

    if (flags & COMM_DOBIND) {
        if (commBind(new_socket, AI) != Comm::OK) {
            comm_close(new_socket);
            return -1;
        }
    }

#ifdef TCP_NODELAY
    if (sock_type == SOCK_STREAM)
        commSetTcpNoDelay(new_socket);

#endif

    if (Config.tcpRcvBufsz > 0 && sock_type == SOCK_STREAM)
        commSetTcpRcvbuf(new_socket, Config.tcpRcvBufsz);

    return new_socket;
}

