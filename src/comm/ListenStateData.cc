/*
 * DEBUG: section 5     Listener Socket Handler
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
#include "CommCalls.h"
#include "comm/AcceptLimiter.h"
#include "comm/comm_internal.h"
#include "comm/ListenStateData.h"
#include "ConnectionDetail.h"
#include "fde.h"
#include "SquidTime.h"

/*
 * This is not strictly needed at all.
 * It's only needed by the cachemgr interface to list the currently active sockets.
 * which could be done for HTTP/HTTPS by listing the http_port_list->listener->fd
 * BUT, FTP data connections is a bit of a problem.
 *
 * AYJ: for now the old way of doing Comm:: actions sequentially in some caller
 *      requires this to anchor each of those Comm:: functions together.
 */
std::map<int, Comm::ListenStateData*> Comm::CurrentListenerSockets;

/**
 * Set of listener sockets which are known to have events pending but we
 * do not have enough sockets available to do the accept just yet.
 */
//std::list<Comm::ListenStateData*> Comm::PendingAccepts;


/**
 * New-style listen and accept routines
 *
 * Listen simply registers our interest in an FD for listening,
 * and accept takes a callback to call when an FD has been
 * accept()ed.
 */
int
Comm::comm_listen(int sock)
{
    int x;

    if ((x = listen(sock, Squid_MaxFD >> 2)) < 0) {
        debugs(50, 0, HERE << "listen(" << (Squid_MaxFD >> 2) << ", " << sock << "): " << xstrerror());
        return x;
    }

    if (Config.accept_filter && strcmp(Config.accept_filter, "none") != 0) {
#ifdef SO_ACCEPTFILTER
        struct accept_filter_arg afa;
        bzero(&afa, sizeof(afa));
        debugs(5, DBG_IMPORTANT, "Installing accept filter '" << Config.accept_filter << "' on FD " << sock);
        xstrncpy(afa.af_name, Config.accept_filter, sizeof(afa.af_name));
        x = setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));
        if (x < 0)
            debugs(5, DBG_CRITICAL, "SO_ACCEPTFILTER '" << Config.accept_filter << "': '" << xstrerror());
#elif defined(TCP_DEFER_ACCEPT)
        int seconds = 30;
        if (strncmp(Config.accept_filter, "data=", 5) == 0)
            seconds = atoi(Config.accept_filter + 5);
        x = setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &seconds, sizeof(seconds));
        if (x < 0)
            debugs(5, DBG_CRITICAL, "TCP_DEFER_ACCEPT '" << Config.accept_filter << "': '" << xstrerror());
#else
        debugs(5, DBG_CRITICAL, "accept_filter not supported on your OS");
#endif
    }

    return sock;
}

// TODO make this a constructor of ListenStateData...
// better yet convert the places its used to setup AsyncCalls instead...
Comm::ListenStateData *
Comm::comm_accept(int fd, IOACB *handler, void *handler_data)
{
    debugs(5, 5, HERE << "FD " << fd << " handler: " << (void*)handler);
    assert(isOpen(fd));

    AsyncCall::Pointer call = commCbCall(5,5, "SomeCommAcceptHandler",
                                         CommAcceptCbPtrFun(handler, handler_data));

    return new Comm::ListenStateData(fd, call, false);
}

Comm::ListenStateData::ListenStateData(int aFd, AsyncCall::Pointer &call, bool accept_many) :
    fd(aFd),
    theCallback(call),
    mayAcceptMore(accept_many)
{
    assert(aFd >= 0);
    debugs(5, 5, HERE << "FD " << fd << " AsyncCall: " << call);
    assert(isOpen(aFd));

    CurrentListenerSockets[fd] = this;

    errcode = comm_listen(fd);
    commSetSelect(fd, COMM_SELECT_READ, doAccept, this, 0);
}

Comm::ListenStateData::~ListenStateData()
{
    // un-register listener before closing the FD.
    // TODO: is this the right way to remove from a std::map<> ?
    if (CurrentListenerSockets[fd])
        CurrentListenerSockets[fd] = NULL;

    comm_close(fd);
    fd = -1;
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
Comm::ListenStateData::doAccept(int fd, void *data)
{
    debugs(5, 2, HERE << "New connection on FD " << fd);

    assert(isOpen(fd));
    ListenStateData *afd = static_cast<ListenStateData*>(data);

    if (!okToAccept()) {
        AcceptLimiter::Instance().defer(afd);
    }
    else {
        afd->acceptNext();
    }
    commSetSelect(fd, COMM_SELECT_READ, Comm::ListenStateData::doAccept, afd, 0);
}

bool
Comm::ListenStateData::okToAccept()
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

bool
Comm::ListenStateData::acceptOne()
{
    /*
     * We don't worry about running low on FDs here.  Instead,
     * doAccept() will use AcceptLimiter if we reach the limit
     * there.
     */

    /* Accept a new connection */
    ConnectionDetail connDetails;
    int newfd = oldAccept(connDetails);

    /* Check for errors */
    if (newfd < 0) {

        if (newfd == COMM_NOMESSAGE) {
            /* register interest again */
            debugs(5, 5, HERE << "try later: FD " << fd << " handler: " << *theCallback);
            commSetSelect(fd, COMM_SELECT_READ, doAccept, this, 0);
            return false;
        }

        // A non-recoverable error; notify the caller */
        debugs(5, 5, HERE << "non-recoverable error: FD " << fd << " handler: " << *theCallback);
        notify(-1, COMM_ERROR, errno, connDetails);
        return false;
    }

    debugs(5, 5, HERE << "accepted: FD " << fd <<
           " newfd: " << newfd << " from: " << connDetails.peer <<
           " handler: " << *theCallback);
    notify(newfd, COMM_OK, 0, connDetails);
    return true;
}

void
Comm::ListenStateData::acceptNext()
{
    assert(isOpen(fd));
    debugs(5, 2, HERE << "connection on FD " << fd);
    mayAcceptMore = acceptOne();
}

void
Comm::ListenStateData::notify(int newfd, comm_err_t errcode, int xerrno, const ConnectionDetail &connDetails)
{
    // listener socket handlers just abandon the port with COMM_ERR_CLOSING
    // it should only happen when this object is deleted...
    if (errcode == COMM_ERR_CLOSING) {
        return;
    }

    if (theCallback != NULL) {
        typedef CommAcceptCbParams Params;
        Params &params = GetCommParams<Params>(theCallback);
        params.fd = fd;
        params.nfd = newfd;
        params.details = connDetails;
        params.flag = errcode;
        params.xerrno = xerrno;
        ScheduleCallHere(theCallback);
        if (!mayAcceptMore)
            theCallback = NULL;
    }
}

/**
 * accept() and process 
 * Wait for an incoming connection on FD.  FD should be a socket returned
 * from comm_listen. */
int
Comm::ListenStateData::oldAccept(ConnectionDetail &details)
{
    PROF_start(comm_accept);
    statCounter.syscalls.sock.accepts++;
    int sock;
    struct addrinfo *gai = NULL;
    details.me.InitAddrInfo(gai);

    if ((sock = accept(fd, gai->ai_addr, &gai->ai_addrlen)) < 0) {

        details.me.FreeAddrInfo(gai);

        PROF_stop(comm_accept);

        if (ignoreErrno(errno)) {
            debugs(50, 5, HERE << "FD " << fd << ": " << xstrerror());
            return COMM_NOMESSAGE;
        } else if (ENFILE == errno || EMFILE == errno) {
            debugs(50, 3, HERE << "FD " << fd << ": " << xstrerror());
            return COMM_ERROR;
        } else {
            debugs(50, 1, HERE << "FD " << fd << ": " << xstrerror());
            return COMM_ERROR;
        }
    }

    details.peer = *gai;

    details.me.InitAddrInfo(gai);

    details.me.SetEmpty();
    getsockname(sock, gai->ai_addr, &gai->ai_addrlen);
    details.me = *gai;

    commSetCloseOnExec(sock);

    /* fdstat update */
    fd_open(sock, FD_SOCKET, "HTTP Request");

    fdd_table[sock].close_file = NULL;
    fdd_table[sock].close_line = 0;

    fde *F = &fd_table[sock];
    details.peer.NtoA(F->ipaddr,MAX_IPSTRLEN);
    F->remote_port = details.peer.GetPort();
    F->local_addr.SetPort(details.me.GetPort());
#if USE_IPV6
    F->sock_family = AF_INET;
#else
    F->sock_family = details.me.IsIPv4()?AF_INET:AF_INET6;
#endif
    details.me.FreeAddrInfo(gai);

    commSetNonBlocking(sock);

    /* IFF the socket is (tproxy) transparent, pass the flag down to allow spoofing */
    F->flags.transparent = fd_table[fd].flags.transparent;

    PROF_stop(comm_accept);
    return sock;
}
