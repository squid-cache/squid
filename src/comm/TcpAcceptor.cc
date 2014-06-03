/*
 * DEBUG: section 05    Listener Socket Handler
 * AUTHOR: Harvest Derived
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
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/TextException.h"
#include "client_db.h"
#include "comm/AcceptLimiter.h"
#include "CommCalls.h"
#include "comm/comm_internal.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/TcpAcceptor.h"
#include "eui/Config.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "ip/Intercept.h"
#include "MasterXaction.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_NETINET_TCP_H
// required for accept_filter to build.
#include <netinet/tcp.h>
#endif

CBDATA_NAMESPACED_CLASS_INIT(Comm, TcpAcceptor);

Comm::TcpAcceptor::TcpAcceptor(const Comm::ConnectionPointer &newConn, const char *note, const Subscription::Pointer &aSub) :
        AsyncJob("Comm::TcpAcceptor"),
        errcode(0),
        isLimited(0),
        theCallSub(aSub),
        conn(newConn)
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
    debugs(5, 5, HERE << status() << " AsyncCall Subscription: " << theCallSub);

    Must(IsConnOpen(conn));

    setListen();

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
    buf.Printf(" FD %d, %s",conn->fd, ipbuf);

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
    errcode = 0; // reset local errno copy.
    if (listen(conn->fd, Squid_MaxFD >> 2) < 0) {
        debugs(50, DBG_CRITICAL, "ERROR: listen(" << status() << ", " << (Squid_MaxFD >> 2) << "): " << xstrerror());
        errcode = errno;
        return;
    }

    if (Config.accept_filter && strcmp(Config.accept_filter, "none") != 0) {
#ifdef SO_ACCEPTFILTER
        struct accept_filter_arg afa;
        bzero(&afa, sizeof(afa));
        debugs(5, DBG_IMPORTANT, "Installing accept filter '" << Config.accept_filter << "' on " << conn);
        xstrncpy(afa.af_name, Config.accept_filter, sizeof(afa.af_name));
        if (setsockopt(conn->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0)
            debugs(5, DBG_CRITICAL, "WARNING: SO_ACCEPTFILTER '" << Config.accept_filter << "': '" << xstrerror());
#elif defined(TCP_DEFER_ACCEPT)
        int seconds = 30;
        if (strncmp(Config.accept_filter, "data=", 5) == 0)
            seconds = atoi(Config.accept_filter + 5);
        if (setsockopt(conn->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &seconds, sizeof(seconds)) < 0)
            debugs(5, DBG_CRITICAL, "WARNING: TCP_DEFER_ACCEPT '" << Config.accept_filter << "': '" << xstrerror());
#else
        debugs(5, DBG_CRITICAL, "WARNING: accept_filter not supported on your OS");
#endif
    }

    typedef CommCbMemFunT<Comm::TcpAcceptor, CommCloseCbParams> Dialer;
    closer_ = JobCallback(5, 4, Dialer, this, Comm::TcpAcceptor::handleClosure);
    comm_add_close_handler(conn->fd, closer_);
}

/// called when listening descriptor is closed by an external force
/// such as clientHttpConnectionsClose()
void
Comm::TcpAcceptor::handleClosure(const CommCloseCbParams &io)
{
    closer_ = NULL;
    conn = NULL;
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
        SetSelect(fd, COMM_SELECT_READ, Comm::TcpAcceptor::doAccept, afd, 0);

    } catch (const std::exception &e) {
        fatalf("FATAL: error while accepting new client connection: %s\n", e.what());
    } catch (...) {
        fatal("FATAL: error while accepting new client connection: [unkown]\n");
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
Comm::TcpAcceptor::acceptOne()
{
    /*
     * We don't worry about running low on FDs here.  Instead,
     * doAccept() will use AcceptLimiter if we reach the limit
     * there.
     */

    /* Accept a new connection */
    ConnectionPointer newConnDetails = new Connection();
    const comm_err_t flag = oldAccept(newConnDetails);

    /* Check for errors */
    if (!newConnDetails->isOpen()) {

        if (flag == COMM_NOMESSAGE) {
            /* register interest again */
            debugs(5, 5, HERE << "try later: " << conn << " handler Subscription: " << theCallSub);
            SetSelect(conn->fd, COMM_SELECT_READ, doAccept, this, 0);
            return;
        }

        // A non-recoverable error; notify the caller */
        debugs(5, 5, HERE << "non-recoverable error:" << status() << " handler Subscription: " << theCallSub);
        notify(flag, newConnDetails);
        mustStop("Listener socket closed");
        return;
    }

    debugs(5, 5, HERE << "Listener: " << conn <<
           " accepted new connection " << newConnDetails <<
           " handler Subscription: " << theCallSub);
    notify(flag, newConnDetails);
}

void
Comm::TcpAcceptor::acceptNext()
{
    Must(IsConnOpen(conn));
    debugs(5, 2, HERE << "connection on " << conn);
    acceptOne();
}

void
Comm::TcpAcceptor::notify(const comm_err_t flag, const Comm::ConnectionPointer &newConnDetails) const
{
    // listener socket handlers just abandon the port with COMM_ERR_CLOSING
    // it should only happen when this object is deleted...
    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    if (theCallSub != NULL) {
        AsyncCall::Pointer call = theCallSub->callback();
        CommAcceptCbParams &params = GetCommParams<CommAcceptCbParams>(call);
        params.xaction = new MasterXaction;
        params.xaction->squidPort = static_cast<AnyP::PortCfg*>(params.data);
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
 * \retval COMM_OK         success. details parameter filled.
 * \retval COMM_NOMESSAGE  attempted accept() but nothing useful came in.
 * \retval COMM_ERROR      an outright failure occured.
 *                         Or if this client has too many connections already.
 */
comm_err_t
Comm::TcpAcceptor::oldAccept(Comm::ConnectionPointer &details)
{
    PROF_start(comm_accept);
    ++statCounter.syscalls.sock.accepts;
    int sock;
    struct addrinfo *gai = NULL;
    Ip::Address::InitAddrInfo(gai);

    errcode = 0; // reset local errno copy.
    if ((sock = accept(conn->fd, gai->ai_addr, &gai->ai_addrlen)) < 0) {
        errcode = errno; // store last accept errno locally.

        Ip::Address::FreeAddrInfo(gai);

        PROF_stop(comm_accept);

        if (ignoreErrno(errno)) {
            debugs(50, 5, HERE << status() << ": " << xstrerror());
            return COMM_NOMESSAGE;
        } else if (ENFILE == errno || EMFILE == errno) {
            debugs(50, 3, HERE << status() << ": " << xstrerror());
            return COMM_ERROR;
        } else {
            debugs(50, DBG_IMPORTANT, HERE << status() << ": " << xstrerror());
            return COMM_ERROR;
        }
    }

    Must(sock >= 0);
    details->fd = sock;
    details->remote = *gai;

    if ( Config.client_ip_max_connections >= 0) {
        if (clientdbEstablished(details->remote, 0) > Config.client_ip_max_connections) {
            debugs(50, DBG_IMPORTANT, "WARNING: " << details->remote << " attempting more than " << Config.client_ip_max_connections << " connections.");
            Ip::Address::FreeAddrInfo(gai);
            return COMM_ERROR;
        }
    }

    // lookup the local-end details of this new connection
    Ip::Address::InitAddrInfo(gai);
    details->local.setEmpty();
    if (getsockname(sock, gai->ai_addr, &gai->ai_addrlen) != 0) {
        debugs(50, DBG_IMPORTANT, "ERROR: getsockname() failed to locate local-IP on " << details << ": " << xstrerror());
        Ip::Address::FreeAddrInfo(gai);
        return COMM_ERROR;
    }
    details->local = *gai;
    Ip::Address::FreeAddrInfo(gai);

    /* fdstat update */
    // XXX : these are not all HTTP requests. use a note about type and ip:port details->
    // so we end up with a uniform "(HTTP|FTP-data|HTTPS|...) remote-ip:remote-port"
    fd_open(sock, FD_SOCKET, "HTTP Request");

    fdd_table[sock].close_file = NULL;
    fdd_table[sock].close_line = 0;

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

    // Perform NAT or TPROXY operations to retrieve the real client/dest IP addresses
    if (conn->flags&(COMM_TRANSPARENT|COMM_INTERCEPTION) && !Ip::Interceptor.Lookup(details, conn)) {
        // Failed.
        return COMM_ERROR;
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

    PROF_stop(comm_accept);
    return COMM_OK;
}
