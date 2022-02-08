/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Connection Opener */

#include "squid.h"
#include "CachePeer.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Loops.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "icmp/net_db.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "SquidConfig.h"
#include "SquidTime.h"

#include <cerrno>

class CachePeer;

CBDATA_NAMESPACED_CLASS_INIT(Comm, ConnOpener);

Comm::ConnOpener::ConnOpener(const Comm::ConnectionPointer &c, const AsyncCall::Pointer &handler, time_t ctimeout) :
    AsyncJob("Comm::ConnOpener"),
    host_(NULL),
    temporaryFd_(-1),
    conn_(c),
    callback_(handler),
    totalTries_(0),
    failRetries_(0),
    deadline_(squid_curtime + static_cast<time_t>(ctimeout))
{
    debugs(5, 3, "will connect to " << c << " with " << ctimeout << " timeout");
    assert(conn_); // we know where to go

    // Sharing a being-modified Connection object with the caller is dangerous,
    // but we cannot ban (or even check for) that using existing APIs. We do not
    // want to clone "just in case" because cloning is a bit expensive, and most
    // callers already have a non-owned Connection object to give us. Until the
    // APIs improve, we can only check that the connection is not open.
    assert(!conn_->isOpen());
}

Comm::ConnOpener::~ConnOpener()
{
    safe_free(host_);
}

bool
Comm::ConnOpener::doneAll() const
{
    // is the conn_ to be opened still waiting?
    if (conn_ == NULL) {
        return AsyncJob::doneAll();
    }

    // is the callback still to be called?
    if (callback_ == NULL || callback_->canceled()) {
        return AsyncJob::doneAll();
    }

    // otherwise, we must be waiting for something
    Must(temporaryFd_ >= 0 || calls_.sleep_);
    return false;
}

void
Comm::ConnOpener::swanSong()
{
    if (callback_ != NULL) {
        // inform the still-waiting caller we are dying
        sendAnswer(Comm::ERR_CONNECT, 0, "Comm::ConnOpener::swanSong");
    }

    // did we abort with a temporary FD assigned?
    if (temporaryFd_ >= 0)
        closeFd();

    // did we abort while owning an open connection?
    if (conn_ && conn_->isOpen())
        conn_->close();

    // did we abort while waiting between retries?
    if (calls_.sleep_)
        cancelSleep();

    AsyncJob::swanSong();
}

void
Comm::ConnOpener::setHost(const char * new_host)
{
    // unset and erase if already set.
    if (host_ != NULL)
        safe_free(host_);

    // set the new one if given.
    if (new_host != NULL)
        host_ = xstrdup(new_host);
}

const char *
Comm::ConnOpener::getHost() const
{
    return host_;
}

/**
 * Connection attempt are completed. One way or the other.
 * Pass the results back to the external handler.
 */
void
Comm::ConnOpener::sendAnswer(Comm::Flag errFlag, int xerrno, const char *why)
{
    // only mark the address good/bad AFTER connect is finished.
    if (host_ != NULL) {
        if (xerrno == 0) // XXX: should not we use errFlag instead?
            ipcacheMarkGoodAddr(host_, conn_->remote);
        else {
            ipcacheMarkBadAddr(host_, conn_->remote);
#if USE_ICMP
            if (Config.onoff.test_reachability)
                netdbDeleteAddrNetwork(conn_->remote);
#endif
        }
    }

    if (callback_ != NULL) {
        // avoid scheduling cancelled callbacks, assuming they are common
        // enough to make this extra check an optimization
        if (callback_->canceled()) {
            debugs(5, 4, conn_ << " not calling canceled " << *callback_ <<
                   " [" << callback_->id << ']' );
            // TODO save the pconn to the pconnPool ?
        } else {
            assert(conn_);

            // free resources earlier and simplify recipients
            if (errFlag != Comm::OK)
                conn_->close(); // may not be opened
            else
                assert(conn_->isOpen());

            typedef CommConnectCbParams Params;
            Params &params = GetCommParams<Params>(callback_);
            params.conn = conn_;
            conn_ = nullptr; // release ownership; prevent closure by us
            params.flag = errFlag;
            params.xerrno = xerrno;
            ScheduleCallHere(callback_);
        }
        callback_ = NULL;
    }

    // The job will stop without this call because nil callback_ makes
    // doneAll() true, but this explicit call creates nicer debugging.
    mustStop(why);
}

/// cleans up this job I/O state without closing temporaryFd
/// required before closing temporaryFd or keeping it in conn_
/// leaves FD bare so must only be called via closeFd() or keepFd()
void
Comm::ConnOpener::cleanFd()
{
    debugs(5, 4, conn_ << "; temp FD " << temporaryFd_);

    Must(temporaryFd_ >= 0);
    fde &f = fd_table[temporaryFd_];

    // Our write_handler was set without using Comm::Write API, so we cannot
    // use a cancellable Pointer-free job callback and simply cancel it here.
    if (f.write_handler) {

        /* XXX: We are about to remove write_handler, which was responsible
         * for deleting write_data, so we have to delete write_data
         * ourselves. Comm currently calls SetSelect handlers synchronously
         * so if write_handler is set, we know it has not been called yet.
         * ConnOpener converts that sync call into an async one, but only
         * after deleting ptr, so that is not a problem.
         */

        delete static_cast<Pointer*>(f.write_data);
        f.write_data = NULL;
        f.write_handler = NULL;
    }
    // Comm::DoSelect does not do this when calling and resetting write_handler
    // (because it expects more writes to come?). We could mimic that
    // optimization by resetting Comm "Select" state only when the FD is
    // actually closed.
    Comm::SetSelect(temporaryFd_, COMM_SELECT_WRITE, NULL, NULL, 0);

    if (calls_.timeout_ != NULL) {
        calls_.timeout_->cancel("Comm::ConnOpener::cleanFd");
        calls_.timeout_ = NULL;
    }
    // Comm checkTimeouts() and commCloseAllSockets() do not clear .timeout
    // when calling timeoutHandler (XXX fix them), so we clear unconditionally.
    f.timeoutHandler = NULL;
    f.timeout = 0;

    if (calls_.earlyAbort_ != NULL) {
        comm_remove_close_handler(temporaryFd_, calls_.earlyAbort_);
        calls_.earlyAbort_ = NULL;
    }
}

/// cleans I/O state and ends I/O for temporaryFd_
void
Comm::ConnOpener::closeFd()
{
    if (temporaryFd_ < 0)
        return;

    cleanFd();

    // comm_close() below uses COMMIO_FD_WRITECB(fd)->active() to clear Comm
    // "Select" state. It will not clear ours. XXX: It should always clear
    // because a callback may have been active but was called before comm_close
    // Update: we now do this in cleanFd()
    // Comm::SetSelect(temporaryFd_, COMM_SELECT_WRITE, NULL, NULL, 0);

    comm_close(temporaryFd_);
    temporaryFd_ = -1;
}

/// cleans I/O state and moves temporaryFd_ to the conn_ for long-term use
void
Comm::ConnOpener::keepFd()
{
    Must(conn_ != NULL);
    Must(temporaryFd_ >= 0);

    cleanFd();

    conn_->fd = temporaryFd_;
    temporaryFd_ = -1;
}

void
Comm::ConnOpener::start()
{
    Must(conn_ != NULL);

    /* outbound sockets have no need to be protocol agnostic. */
    if (!(Ip::EnableIpv6&IPV6_SPECIAL_V4MAPPING) && conn_->remote.isIPv4()) {
        conn_->local.setIPv4();
    }

    conn_->noteStart();
    if (createFd())
        doConnect();
}

/// called at the end of Comm::ConnOpener::DelayedConnectRetry event
void
Comm::ConnOpener::restart()
{
    debugs(5, 5, conn_ << " restarting after sleep");
    calls_.sleep_ = false;

    if (createFd())
        doConnect();
}

/// Create a socket for the future connection or return false.
/// If false is returned, done() is guaranteed to return true and end the job.
bool
Comm::ConnOpener::createFd()
{
    Must(temporaryFd_ < 0);
    assert(conn_);

    // our initators signal abort by cancelling their callbacks
    if (callback_ == NULL || callback_->canceled())
        return false;

    temporaryFd_ = comm_openex(SOCK_STREAM, IPPROTO_TCP, conn_->local, conn_->flags, host_);
    if (temporaryFd_ < 0) {
        sendAnswer(Comm::ERR_CONNECT, 0, "Comm::ConnOpener::createFd");
        return false;
    }

    // Set TOS if needed.
    if (conn_->tos &&
            Ip::Qos::setSockTos(temporaryFd_, conn_->tos, conn_->remote.isIPv4() ? AF_INET : AF_INET6) < 0)
        conn_->tos = 0;
#if SO_MARK
    if (conn_->nfmark &&
            Ip::Qos::setSockNfmark(temporaryFd_, conn_->nfmark) < 0)
        conn_->nfmark = 0;
#endif

    fd_table[temporaryFd_].tosToServer = conn_->tos;
    fd_table[temporaryFd_].nfmarkToServer = conn_->nfmark;

    typedef CommCbMemFunT<Comm::ConnOpener, CommCloseCbParams> abortDialer;
    calls_.earlyAbort_ = JobCallback(5, 4, abortDialer, this, Comm::ConnOpener::earlyAbort);
    comm_add_close_handler(temporaryFd_, calls_.earlyAbort_);

    typedef CommCbMemFunT<Comm::ConnOpener, CommTimeoutCbParams> timeoutDialer;
    calls_.timeout_ = JobCallback(5, 4, timeoutDialer, this, Comm::ConnOpener::timeout);
    debugs(5, 3, conn_ << " will timeout in " << (deadline_ - squid_curtime));

    // Update the fd_table directly because commSetConnTimeout() needs open conn_
    assert(temporaryFd_ < Squid_MaxFD);
    assert(fd_table[temporaryFd_].flags.open);
    typedef CommTimeoutCbParams Params;
    Params &params = GetCommParams<Params>(calls_.timeout_);
    params.conn = conn_;
    fd_table[temporaryFd_].timeoutHandler = calls_.timeout_;
    fd_table[temporaryFd_].timeout = deadline_;

    return true;
}

void
Comm::ConnOpener::connected()
{
    Must(temporaryFd_ >= 0);
    keepFd();

    /*
     * stats.conn_open is used to account for the number of
     * connections that we have open to the CachePeer, so we can limit
     * based on the max-conn option.  We need to increment here,
     * even if the connection may fail.
     */
    if (CachePeer *peer=(conn_->getPeer()))
        ++peer->stats.conn_open;

    lookupLocalAddress();

    /* TODO: remove these fd_table accesses. But old code still depends on fd_table flags to
     *       indicate the state of a raw fd object being passed around.
     *       Also, legacy code still depends on comm_local_port() with no access to Comm::Connection
     *       when those are done comm_local_port can become one of our member functions to do the below.
     */
    Must(fd_table[conn_->fd].flags.open);
    fd_table[conn_->fd].local_addr = conn_->local;

    sendAnswer(Comm::OK, 0, "Comm::ConnOpener::connected");
}

/// Make an FD connection attempt.
void
Comm::ConnOpener::doConnect()
{
    Must(conn_ != NULL);
    Must(temporaryFd_ >= 0);

    ++ totalTries_;

    switch (comm_connect_addr(temporaryFd_, conn_->remote) ) {

    case Comm::INPROGRESS:
        debugs(5, 5, HERE << conn_ << ": Comm::INPROGRESS");
        Comm::SetSelect(temporaryFd_, COMM_SELECT_WRITE, Comm::ConnOpener::InProgressConnectRetry, new Pointer(this), 0);
        break;

    case Comm::OK:
        debugs(5, 5, HERE << conn_ << ": Comm::OK - connected");
        connected();
        break;

    default: {
        const int xerrno = errno;

        ++failRetries_;
        debugs(5, 7, conn_ << ": failure #" << failRetries_ << " <= " <<
               Config.connect_retries << ": " << xstrerr(xerrno));

        if (failRetries_ < Config.connect_retries) {
            debugs(5, 5, HERE << conn_ << ": * - try again");
            retrySleep();
            return;
        } else {
            // send ERROR back to the upper layer.
            debugs(5, 5, HERE << conn_ << ": * - ERR tried too many times already.");
            sendAnswer(Comm::ERR_CONNECT, xerrno, "Comm::ConnOpener::doConnect");
        }
    }
    }
}

/// Close and wait a little before trying to open and connect again.
void
Comm::ConnOpener::retrySleep()
{
    Must(!calls_.sleep_);
    closeFd();
    calls_.sleep_ = true;
    eventAdd("Comm::ConnOpener::DelayedConnectRetry",
             Comm::ConnOpener::DelayedConnectRetry,
             new Pointer(this), 0.05, 0, false);
}

/// cleans up this job sleep state
void
Comm::ConnOpener::cancelSleep()
{
    if (calls_.sleep_) {
        // It would be nice to delete the sleep event, but it might be out of
        // the event queue and in the async queue already, so (a) we do not know
        // whether we can safely delete the call ptr here and (b) eventDelete()
        // will assert if the event went async. Thus, we let the event run so
        // that it deletes the call ptr [after this job is gone]. Note that we
        // are called only when the job ends so this "hanging event" will do
        // nothing but deleting the call ptr.  TODO: Revise eventDelete() API.
        // eventDelete(Comm::ConnOpener::DelayedConnectRetry, calls_.sleep);
        calls_.sleep_ = false;
        debugs(5, 9, conn_ << " stops sleeping");
    }
}

/**
 * Lookup local-end address and port of the TCP link just opened.
 * This ensure the connection local details are set correctly
 */
void
Comm::ConnOpener::lookupLocalAddress()
{
    struct addrinfo *addr = NULL;
    Ip::Address::InitAddr(addr);

    if (getsockname(conn_->fd, addr->ai_addr, &(addr->ai_addrlen)) != 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: Failed to retrieve TCP/UDP details for socket: " << conn_ << ": " << xstrerr(xerrno));
        Ip::Address::FreeAddr(addr);
        return;
    }

    conn_->local = *addr;
    Ip::Address::FreeAddr(addr);
    debugs(5, 6, HERE << conn_);
}

/** Abort connection attempt.
 * Handles the case(s) when a partially setup connection gets closed early.
 */
void
Comm::ConnOpener::earlyAbort(const CommCloseCbParams &io)
{
    debugs(5, 3, HERE << io.conn);
    calls_.earlyAbort_ = NULL;
    // NP: is closing or shutdown better?
    sendAnswer(Comm::ERR_CLOSING, io.xerrno, "Comm::ConnOpener::earlyAbort");
}

/**
 * Handles the case(s) when a partially setup connection gets timed out.
 * NP: When commSetConnTimeout accepts generic CommCommonCbParams this can die.
 */
void
Comm::ConnOpener::timeout(const CommTimeoutCbParams &)
{
    debugs(5, 5, HERE << conn_ << ": * - ERR took too long to receive response.");
    calls_.timeout_ = NULL;
    sendAnswer(Comm::TIMEOUT, ETIMEDOUT, "Comm::ConnOpener::timeout");
}

/* Legacy Wrapper for the retry event after Comm::INPROGRESS
 * XXX: As soon as Comm::SetSelect() accepts Async calls we can use a ConnOpener::doConnect call
 */
void
Comm::ConnOpener::InProgressConnectRetry(int, void *data)
{
    Pointer *ptr = static_cast<Pointer*>(data);
    assert(ptr);
    if (ConnOpener *cs = ptr->valid()) {
        // Ew. we are now outside the all AsyncJob protections.
        // get back inside by scheduling another call...
        typedef NullaryMemFunT<Comm::ConnOpener> Dialer;
        AsyncCall::Pointer call = JobCallback(5, 4, Dialer, cs, Comm::ConnOpener::doConnect);
        ScheduleCallHere(call);
    }
    delete ptr;
}

/* Legacy Wrapper for the retry event with small delay after errors.
 * XXX: As soon as eventAdd() accepts Async calls we can use a ConnOpener::restart call
 */
void
Comm::ConnOpener::DelayedConnectRetry(void *data)
{
    Pointer *ptr = static_cast<Pointer*>(data);
    assert(ptr);
    if (ConnOpener *cs = ptr->valid()) {
        // Ew. we are now outside the all AsyncJob protections.
        // get back inside by scheduling another call...
        typedef NullaryMemFunT<Comm::ConnOpener> Dialer;
        AsyncCall::Pointer call = JobCallback(5, 4, Dialer, cs, Comm::ConnOpener::restart);
        ScheduleCallHere(call);
    }
    delete ptr;
}

