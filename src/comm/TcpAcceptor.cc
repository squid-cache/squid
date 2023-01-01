/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Listener Socket Handler */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "anyp/PortCfg.h"
#include "base/TextException.h"
#include "client_db.h"
#include "comm/AcceptLimiter.h"
#include "comm/comm_internal.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/TcpAcceptor.h"
#include "CommCalls.h"
#include "eui/Config.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "log/access_log.h"
#include "MasterXaction.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"

#include <cerrno>
#ifdef HAVE_NETINET_TCP_H
// required for accept_filter to build.
#include <netinet/tcp.h>
#endif

CBDATA_NAMESPACED_CLASS_INIT(Comm, TcpAcceptor);

Comm::TcpAcceptor::TcpAcceptor(const Comm::ConnectionPointer &newConn, const char *, const Subscription::Pointer &aSub) :
    AsyncJob("Comm::TcpAcceptor"),
    errcode(0),
    theCallSub(aSub),
    conn(newConn),
    listenPort_()
{}

Comm::TcpAcceptor::TcpAcceptor(const AnyP::PortCfgPointer &p, const char *, const Subscription::Pointer &aSub) :
    AsyncJob("Comm::TcpAcceptor"),
    errcode(0),
    theCallSub(aSub),
    conn(p->listenConn),
    listenPort_(p)
{}

void
Comm::TcpAcceptor::subscribe(const Subscription::Pointer &aSub)
{
    debugs(5, 5, HERE << status() << " AsyncCall Subscription: " << aSub);
    unsubscribe("subscription change");
    theCallSub = aSub;
}

void
Comm::TcpAcceptor::unsubscribe(const char *reason)
{
    debugs(5, 5, HERE << status() << " AsyncCall Subscription " << theCallSub << " removed: " << reason);
    theCallSub = NULL;
}

void
Comm::TcpAcceptor::start()
{
    if (listenPort_)
        CodeContext::Reset(listenPort_);
    debugs(5, 5, HERE << status() << " AsyncCall Subscription: " << theCallSub);

    Must(IsConnOpen(conn));

    setListen();

    conn->noteStart();

    // if no error so far start accepting connections.
    if (errcode == 0)
        SetSelect(conn->fd, COMM_SELECT_READ, doAccept, this, 0);
}

bool
Comm::TcpAcceptor::doneAll() const
{
    // stop when FD is closed
    if (!IsConnOpen(conn)) {
        return AsyncJob::doneAll();
    }

    // stop when handlers are gone
    if (theCallSub == NULL) {
        return AsyncJob::doneAll();
    }

    // open FD with handlers...keep accepting.
    return false;
}

void
Comm::TcpAcceptor::swanSong()
{
    debugs(5,5, HERE);
    unsubscribe("swanSong");
    if (IsConnOpen(conn)) {
        if (closer_ != NULL)
            comm_remove_close_handler(conn->fd, closer_);
        conn->close();
    }

    conn = NULL;
    AcceptLimiter::Instance().removeDead(this);
    AsyncJob::swanSong();
}

const char *
Comm::TcpAcceptor::status() const
{
    if (conn == NULL)
        return "[nil connection]";

    static char ipbuf[MAX_IPSTRLEN] = {'\0'};
    if (ipbuf[0] == '\0')
        conn->local.toHostStr(ipbuf, MAX_IPSTRLEN);

    static MemBuf buf;
    buf.reset();
    buf.appendf(" FD %d, %s",conn->fd, ipbuf);

    const char *jobStatus = AsyncJob::status();
    buf.append(jobStatus, strlen(jobStatus));

    return buf.content();
}

/**
 * New-style listen and accept routines
 *
 * setListen simply registers our interest in an FD for listening.
 * The constructor takes a callback to call when an FD has been
 * accept()ed some time later.
 */
void
Comm::TcpAcceptor::setListen()
{
    errcode = errno = 0;
    if (listen(conn->fd, Squid_MaxFD >> 2) < 0) {
        errcode = errno;
        debugs(50, DBG_CRITICAL, "ERROR: listen(..., " << (Squid_MaxFD >> 2) << ") system call failed: " << xstrerr(errcode));
        return;
    }

    if (Config.accept_filter && strcmp(Config.accept_filter, "none") != 0) {
#ifdef SO_ACCEPTFILTER
        struct accept_filter_arg afa;
        bzero(&afa, sizeof(afa));
        debugs(5, DBG_IMPORTANT, "Installing accept filter '" << Config.accept_filter << "' on " << conn);
        xstrncpy(afa.af_name, Config.accept_filter, sizeof(afa.af_name));
        if (setsockopt(conn->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0) {
            int xerrno = errno;
            debugs(5, DBG_CRITICAL, "WARNING: SO_ACCEPTFILTER '" << Config.accept_filter << "': '" << xstrerr(xerrno));
        }
#elif defined(TCP_DEFER_ACCEPT)
        int seconds = 30;
        if (strncmp(Config.accept_filter, "data=", 5) == 0)
            seconds = atoi(Config.accept_filter + 5);
        if (setsockopt(conn->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &seconds, sizeof(seconds)) < 0) {
            int xerrno = errno;
            debugs(5, DBG_CRITICAL, "WARNING: TCP_DEFER_ACCEPT '" << Config.accept_filter << "': '" << xstrerr(xerrno));
        }
#else
        debugs(5, DBG_CRITICAL, "WARNING: accept_filter not supported on your OS");
#endif
    }

#if 0
    // Untested code.
    // Set TOS if needed.
    // To correctly implement TOS values on listening sockets, probably requires
    // more work to inherit TOS values to created connection objects.
    if (conn->tos)
        Ip::Qos::setSockTos(conn, conn->tos)
#if SO_MARK
        if (conn->nfmark)
            Ip::Qos::setSockNfmark(conn, conn->nfmark);
#endif
#endif

    typedef CommCbMemFunT<Comm::TcpAcceptor, CommCloseCbParams> Dialer;
    closer_ = JobCallback(5, 4, Dialer, this, Comm::TcpAcceptor::handleClosure);
    comm_add_close_handler(conn->fd, closer_);
}

/// called when listening descriptor is closed by an external force
/// such as clientHttpConnectionsClose()
void
Comm::TcpAcceptor::handleClosure(const CommCloseCbParams &)
{
    closer_ = NULL;
    if (conn) {
        conn->noteClosure();
        conn = nullptr;
    }
    Must(done());
}

/**
 * This private callback is called whenever a filedescriptor is ready
 * to dupe itself and fob off an accept()ed connection
 *
 * It will either do that accept operation. Or if there are not enough FD
 * available to do the clone safely will push the listening FD into a list
 * of deferred operations. The list gets kicked and the dupe/accept() actually
 * done later when enough sockets become available.
 */
void
Comm::TcpAcceptor::doAccept(int fd, void *data)
{
    try {
        debugs(5, 2, HERE << "New connection on FD " << fd);

        Must(isOpen(fd));
        TcpAcceptor *afd = static_cast<TcpAcceptor*>(data);

        if (!okToAccept()) {
            AcceptLimiter::Instance().defer(afd);
        } else {
            afd->acceptNext();
        }

    } catch (const std::exception &e) {
        fatalf("FATAL: error while accepting new client connection: %s\n", e.what());
    } catch (...) {
        fatal("FATAL: error while accepting new client connection: [unknown]\n");
    }
}

bool
Comm::TcpAcceptor::okToAccept()
{
    static time_t last_warn = 0;

    if (fdNFree() >= RESERVED_FD)
        return true;

    if (last_warn + 15 < squid_curtime) {
        debugs(5, DBG_CRITICAL, "WARNING! Your cache is running out of filedescriptors");
        last_warn = squid_curtime;
    }

    return false;
}

void
Comm::TcpAcceptor::logAcceptError(const ConnectionPointer &tcpClient) const
{
    AccessLogEntry::Pointer al = new AccessLogEntry;
    CodeContext::Reset(al);
    al->tcpClient = tcpClient;
    al->url = "error:accept-client-connection";
    al->setVirginUrlForMissingRequest(al->url);
    ACLFilledChecklist ch(nullptr, nullptr, nullptr);
    ch.src_addr = tcpClient->remote;
    ch.my_addr = tcpClient->local;
    ch.al = al;
    accessLogLog(al, &ch);

    CodeContext::Reset(listenPort_);
}

void
Comm::TcpAcceptor::acceptOne()
{
    /*
     * We don't worry about running low on FDs here.  Instead,
     * doAccept() will use AcceptLimiter if we reach the limit
     * there.
     */

    /* Accept a new connection */
    ConnectionPointer newConnDetails = new Connection();
    const Comm::Flag flag = oldAccept(newConnDetails);

    if (flag == Comm::COMM_ERROR) {
        // A non-recoverable error; notify the caller */
        debugs(5, 5, HERE << "non-recoverable error:" << status() << " handler Subscription: " << theCallSub);
        if (intendedForUserConnections())
            logAcceptError(newConnDetails);
        notify(flag, newConnDetails);
        mustStop("Listener socket closed");
        return;
    }

    if (flag == Comm::NOMESSAGE) {
        /* register interest again */
        debugs(5, 5, "try later: " << conn << " handler Subscription: " << theCallSub);
    } else {
        // TODO: When ALE, MasterXaction merge, use them or ClientConn instead.
        CodeContext::Reset(newConnDetails);
        debugs(5, 5, "Listener: " << conn <<
               " accepted new connection " << newConnDetails <<
               " handler Subscription: " << theCallSub);
        notify(flag, newConnDetails);
        CodeContext::Reset(listenPort_);
    }

    SetSelect(conn->fd, COMM_SELECT_READ, doAccept, this, 0);
}

void
Comm::TcpAcceptor::acceptNext()
{
    Must(IsConnOpen(conn));
    debugs(5, 2, HERE << "connection on " << conn);
    acceptOne();
}

void
Comm::TcpAcceptor::notify(const Comm::Flag flag, const Comm::ConnectionPointer &newConnDetails) const
{
    // listener socket handlers just abandon the port with Comm::ERR_CLOSING
    // it should only happen when this object is deleted...
    if (flag == Comm::ERR_CLOSING) {
        return;
    }

    if (theCallSub != NULL) {
        AsyncCall::Pointer call = theCallSub->callback();
        CommAcceptCbParams &params = GetCommParams<CommAcceptCbParams>(call);
        params.xaction = new MasterXaction(XactionInitiator::initClient);
        params.xaction->squidPort = listenPort_;
        params.fd = conn->fd;
        params.conn = params.xaction->tcpClient = newConnDetails;
        params.flag = flag;
        params.xerrno = errcode;
        ScheduleCallHere(call);
    }
}

/**
 * accept() and process
 * Wait for an incoming connection on our listener socket.
 *
 * \retval Comm::OK          success. details parameter filled.
 * \retval Comm::NOMESSAGE   attempted accept() but nothing useful came in.
 *                           Or this client has too many connections already.
 * \retval Comm::COMM_ERROR  an outright failure occurred.
 */
Comm::Flag
Comm::TcpAcceptor::oldAccept(Comm::ConnectionPointer &details)
{
    PROF_start(comm_accept);
    ++statCounter.syscalls.sock.accepts;
    int sock;
    struct addrinfo *gai = NULL;
    Ip::Address::InitAddr(gai);

    errcode = 0; // reset local errno copy.
    if ((sock = accept(conn->fd, gai->ai_addr, &gai->ai_addrlen)) < 0) {
        errcode = errno; // store last accept errno locally.

        Ip::Address::FreeAddr(gai);

        PROF_stop(comm_accept);

        if (ignoreErrno(errcode) || errcode == ECONNABORTED) {
            debugs(50, 5, status() << ": " << xstrerr(errcode));
            return Comm::NOMESSAGE;
        } else if (errcode == ENFILE || errcode == EMFILE) {
            debugs(50, 3, status() << ": " << xstrerr(errcode));
            return Comm::COMM_ERROR;
        } else {
            debugs(50, DBG_IMPORTANT, "ERROR: failed to accept an incoming connection: " << xstrerr(errcode));
            return Comm::COMM_ERROR;
        }
    }

    Must(sock >= 0);

    // Sync with Comm ASAP so that abandoned details can properly close().
    // XXX : these are not all HTTP requests. use a note about type and ip:port details->
    // so we end up with a uniform "(HTTP|FTP-data|HTTPS|...) remote-ip:remote-port"
    fd_open(sock, FD_SOCKET, "HTTP Request");
    details->fd = sock;

    details->remote = *gai;

    // lookup the local-end details of this new connection
    Ip::Address::InitAddr(gai);
    details->local.setEmpty();
    if (getsockname(sock, gai->ai_addr, &gai->ai_addrlen) != 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: getsockname() failed to locate local-IP on " << details << ": " << xstrerr(xerrno));
        Ip::Address::FreeAddr(gai);
        PROF_stop(comm_accept);
        return Comm::COMM_ERROR;
    }
    details->local = *gai;
    Ip::Address::FreeAddr(gai);

    // Perform NAT or TPROXY operations to retrieve the real client/dest IP addresses
    if (conn->flags&(COMM_TRANSPARENT|COMM_INTERCEPTION) && !Ip::Interceptor.Lookup(details, conn)) {
        debugs(50, DBG_IMPORTANT, "ERROR: NAT/TPROXY lookup failed to locate original IPs on " << details);
        // Failed.
        PROF_stop(comm_accept);
        return Comm::COMM_ERROR;
    }

#if USE_SQUID_EUI
    if (Eui::TheConfig.euiLookup) {
        if (details->remote.isIPv4()) {
            details->remoteEui48.lookup(details->remote);
        } else if (details->remote.isIPv6()) {
            details->remoteEui64.lookup(details->remote);
        }
    }
#endif

    details->nfConnmark = Ip::Qos::getNfConnmark(details, Ip::Qos::dirAccepted);

    if (Config.client_ip_max_connections >= 0) {
        if (clientdbEstablished(details->remote, 0) > Config.client_ip_max_connections) {
            debugs(50, DBG_IMPORTANT, "WARNING: " << details->remote << " attempting more than " << Config.client_ip_max_connections << " connections.");
            PROF_stop(comm_accept);
            return Comm::NOMESSAGE;
        }
    }

    fde *F = &fd_table[sock];
    details->remote.toStr(F->ipaddr,MAX_IPSTRLEN);
    F->remote_port = details->remote.port();
    F->local_addr = details->local;
    F->sock_family = details->local.isIPv6()?AF_INET6:AF_INET;

    // set socket flags
    commSetCloseOnExec(sock);
    commSetNonBlocking(sock);

    /* IFF the socket is (tproxy) transparent, pass the flag down to allow spoofing */
    F->flags.transparent = fd_table[conn->fd].flags.transparent; // XXX: can we remove this line yet?

    PROF_stop(comm_accept);
    return Comm::OK;
}

