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
#include "base/TextException.h"
#include "CommCalls.h"
#include "comm/AcceptLimiter.h"
#include "comm/comm_internal.h"
#include "comm/Connection.h"
#include "comm/ConnAcceptor.h"
#include "fde.h"
#include "protos.h"
#include "SquidTime.h"

namespace Comm {
    CBDATA_CLASS_INIT(ConnAcceptor);
};

Comm::ConnAcceptor::ConnAcceptor(const Comm::ConnectionPointer &newConn, const char *note, const Subscription::Pointer &aSub) :
        AsyncJob("Comm::ConnAcceptor"),
        errcode(0),
        isLimited(0),
        theCallSub(aSub),
        conn(newConn)
{
    assert(newConn != NULL);

    /* open the conn if its not already open */
    if (!IsConnOpen(conn)) {
        conn->fd = comm_open_listener(SOCK_STREAM, IPPROTO_TCP, conn->local, conn->flags, note);
        errcode = errno;

        if (!conn->isOpen()) {
            debugs(5, DBG_CRITICAL, HERE << "comm_open failed: " << conn << " error: " << errcode);
            conn = NULL;
            return;
        }
        debugs(9, 3, HERE << "Unconnected data socket created on " << conn);
    }
    assert(IsConnOpen(newConn));
}

void
Comm::ConnAcceptor::subscribe(const Subscription::Pointer &aSub)
{
    debugs(5, 5, HERE << conn << " AsyncCall Subscription: " << aSub);
    unsubscribe("subscription change");
    theCallSub = aSub;
}

void
Comm::ConnAcceptor::unsubscribe(const char *reason)
{
    debugs(5, 5, HERE << conn << " AsyncCall Subscription " << theCallSub << " removed: " << reason);
    theCallSub = NULL;
}

void
Comm::ConnAcceptor::start()
{
    debugs(5, 5, HERE << conn << " AsyncCall Subscription: " << theCallSub);

    Must(IsConnOpen(conn));

    setListen();

    // if no error so far start accepting connections.
    if (errcode == 0)
        commSetSelect(conn->fd, COMM_SELECT_READ, doAccept, this, 0);
}

bool
Comm::ConnAcceptor::doneAll() const
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
Comm::ConnAcceptor::swanSong()
{
    debugs(5,5, HERE);
    unsubscribe("swanSong");
    conn = NULL;
    AcceptLimiter::Instance().removeDead(this);
    AsyncJob::swanSong();
}

/**
 * New-style listen and accept routines
 *
 * setListen simply registers our interest in an FD for listening.
 * The constructor takes a callback to call when an FD has been
 * accept()ed some time later.
 */
void
Comm::ConnAcceptor::setListen()
{
    errcode = 0; // reset local errno copy.
    if (listen(conn->fd, Squid_MaxFD >> 2) < 0) {
        debugs(50, DBG_CRITICAL, "ERROR: listen(" << conn << ", " << (Squid_MaxFD >> 2) << "): " << xstrerror());
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
Comm::ConnAcceptor::doAccept(int fd, void *data)
{
    try {
        debugs(5, 2, HERE << "New connection on FD " << fd);

        Must(isOpen(fd));
        ConnAcceptor *afd = static_cast<ConnAcceptor*>(data);

        if (!okToAccept()) {
            AcceptLimiter::Instance().defer(afd);
        } else {
            afd->acceptNext();
        }
        commSetSelect(fd, COMM_SELECT_READ, Comm::ConnAcceptor::doAccept, afd, 0);

    } catch(const TextException &e) {
        fatalf("FATAL: error while accepting new client connection: %s\n", e.message);
    } catch(...) {
        fatal("FATAL: error while accepting new client connection: [unkown]\n");
    }
}

bool
Comm::ConnAcceptor::okToAccept()
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
Comm::ConnAcceptor::acceptOne()
{
    /*
     * We don't worry about running low on FDs here.  Instead,
     * doAccept() will use AcceptLimiter if we reach the limit
     * there.
     */

    /* Accept a new connection */
    ConnectionPointer newConnDetails = new Connection();
    comm_err_t status = oldAccept(newConnDetails);

    /* Check for errors */
    if (!newConnDetails->isOpen()) {

        if (status == COMM_NOMESSAGE) {
            /* register interest again */
            debugs(5, 5, HERE << "try later: " << conn << " handler Subscription: " << theCallSub);
            commSetSelect(conn->fd, COMM_SELECT_READ, doAccept, this, 0);
            return;
        }

        // A non-recoverable error; notify the caller */
        debugs(5, 5, HERE << "non-recoverable error: " << conn << " handler Subscription: " << theCallSub);
        notify(status, newConnDetails);
        mustStop("Listener socket closed");
        return;
    }

    debugs(5, 5, HERE << "Listener: " << conn <<
           " accepted new connection " << newConnDetails <<
           " handler Subscription: " << theCallSub);
    notify(status, newConnDetails);
}

void
Comm::ConnAcceptor::acceptNext()
{
    Must(IsConnOpen(conn));
    debugs(5, 2, HERE << "connection on " << conn);
    acceptOne();
}

// XXX: obsolete comment?
// NP: can't be a const function because syncWithComm() side effects hit theCallSub->callback().
void
Comm::ConnAcceptor::notify(comm_err_t flag, const Comm::ConnectionPointer &newConnDetails)
{
    // listener socket handlers just abandon the port with COMM_ERR_CLOSING
    // it should only happen when this object is deleted...
    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    if (theCallSub != NULL) {
        AsyncCall::Pointer call = theCallSub->callback();
        CommAcceptCbParams &params = GetCommParams<CommAcceptCbParams>(call);
        params.fd = conn->fd;
        params.conn = newConnDetails;
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
Comm::ConnAcceptor::oldAccept(Comm::ConnectionPointer &details)
{
    PROF_start(comm_accept);
    statCounter.syscalls.sock.accepts++;
    int sock;
    struct addrinfo *gai = NULL;
    details->local.InitAddrInfo(gai);

    errcode = 0; // reset local errno copy.
    if ((sock = accept(conn->fd, gai->ai_addr, &gai->ai_addrlen)) < 0) {
        errcode = errno; // store last accept errno locally.

        details->local.FreeAddrInfo(gai);

        PROF_stop(comm_accept);

        if (ignoreErrno(errno)) {
            debugs(50, 5, HERE << conn << ": " << xstrerror());
            return COMM_NOMESSAGE;
        } else if (ENFILE == errno || EMFILE == errno) {
            debugs(50, 3, HERE << conn << ": " << xstrerror());
            return COMM_ERROR;
        } else {
            debugs(50, 1, HERE << conn << ": " << xstrerror());
            return COMM_ERROR;
        }
    }

    Must(sock >= 0);
    details->fd = sock;
    details->remote = *gai;

    if ( Config.client_ip_max_connections >= 0) {
        if (clientdbEstablished(details->remote, 0) > Config.client_ip_max_connections) {
            debugs(50, DBG_IMPORTANT, "WARNING: " << details->remote << " attempting more than " << Config.client_ip_max_connections << " connections.");
            details->local.FreeAddrInfo(gai);
            return COMM_ERROR;
        }
    }

    // lookup the local-end details of this new connection
    details->local.InitAddrInfo(gai);
    details->local.SetEmpty();
    getsockname(sock, gai->ai_addr, &gai->ai_addrlen);
    details->local = *gai;
    details->local.FreeAddrInfo(gai);

    /* fdstat update */
    // XXX : these are not all HTTP requests. use a note about type and ip:port details->
    // so we end up with a uniform "(HTTP|FTP-data|HTTPS|...) remote-ip:remote-port"
    fd_open(sock, FD_SOCKET, "HTTP Request");

    fdd_table[sock].close_file = NULL;
    fdd_table[sock].close_line = 0;

    fde *F = &fd_table[sock];
    details->remote.NtoA(F->ipaddr,MAX_IPSTRLEN);
    F->remote_port = details->remote.GetPort();
    F->local_addr = details->local;
    F->sock_family = details->local.IsIPv6()?AF_INET6:AF_INET;

    // set socket flags
    commSetCloseOnExec(sock);
    commSetNonBlocking(sock);

    /* IFF the socket is (tproxy) transparent, pass the flag down to allow spoofing */
    F->flags.transparent = fd_table[conn->fd].flags.transparent;

    PROF_stop(comm_accept);
    return COMM_OK;
}
