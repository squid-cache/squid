/*
 * DEBUG: section 05    Socket Connection Opener
 */

#include "config.h"
#include "base/TextException.h"
#include "comm/ConnOpener.h"
#include "comm/Connection.h"
#include "comm.h"
#include "fde.h"
#include "icmp/net_db.h"
#include "SquidTime.h"

namespace Comm {
    CBDATA_CLASS_INIT(ConnOpener);
};

Comm::ConnOpener::ConnOpener(Comm::ConnectionPointer &c, AsyncCall::Pointer &handler, time_t ctimeout) :
        AsyncJob("Comm::ConnOpener"),
        host_(NULL),
        conn_(c),
        callback_(handler),
        totalTries_(0),
        failRetries_(0),
        connectTimeout_(ctimeout),
        connStart_(0)
{}

Comm::ConnOpener::~ConnOpener()
{
    safe_free(host_);
}

bool
Comm::ConnOpener::doneAll() const
{
    // is the conn_ to be opened still waiting?
    if (conn_ != NULL) {
        return false;
    }

    // is the callback still to be called?
    if (callback_ != NULL) {
        return false;
    }

    return AsyncJob::doneAll();
}

void
Comm::ConnOpener::swanSong()
{
    // cancel any event watchers
    // done here to get the "swanSong" mention in cancel debugging.
    if (calls_.earlyAbort_ != NULL) {
        calls_.earlyAbort_->cancel("Comm::ConnOpener::swanSong");
        calls_.earlyAbort_ = NULL;
    }
    if (calls_.timeout_ != NULL) {
        calls_.timeout_->cancel("Comm::ConnOpener::swanSong");
        calls_.timeout_ = NULL;
    }

    // recover what we can from the job
    if (conn_ != NULL && conn_->isOpen()) {
        // it never reached fully open, so abort the FD
        conn_->close();
        fd_table[conn_->fd].flags.open = 0;
        // inform the caller
        doneConnecting(COMM_ERR_CONNECT, 0);
    }
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
Comm::ConnOpener::doneConnecting(comm_err_t status, int xerrno)
{
    if (callback_ != NULL) {
        typedef CommConnectCbParams Params;
        Params &params = GetCommParams<Params>(callback_);
        params.conn = conn_;
        params.flag = status;
        params.xerrno = xerrno;
        ScheduleCallHere(callback_);
        callback_ = NULL;
    }

    /* ensure cleared local state, we are done. */
    conn_ = NULL;
}

void Comm::ConnOpener::start()
{
    Must(conn_ != NULL);

    /* get a socket open ready for connecting with */
    if (!conn_->isOpen()) {
#if USE_IPV6
        /* outbound sockets have no need to be protocol agnostic. */
        if (conn_->remote.IsIPv4()) {
            conn_->local.SetIPv4();
        }
#endif
        conn_->fd = comm_openex(SOCK_STREAM, IPPROTO_TCP, conn_->local, conn_->flags, conn_->tos, host_);
        if (!conn_->isOpen()) {
            doneConnecting(COMM_ERR_CONNECT, 0);
            return;
        }

        if (calls_.earlyAbort_ == NULL) {
            typedef CommCbMemFunT<Comm::ConnOpener, CommConnectCbParams> Dialer;
            calls_.earlyAbort_ = asyncCall(5, 4, "Comm::ConnOpener::earlyAbort",
                                         Dialer(this, &Comm::ConnOpener::earlyAbort));
            comm_add_close_handler(conn_->fd, calls_.earlyAbort_);
        }

        if (calls_.timeout_ == NULL) {
            typedef CommCbMemFunT<Comm::ConnOpener, CommTimeoutCbParams> Dialer;
            calls_.timeout_ = asyncCall(5, 4, "Comm::ConnOpener::timeout",
                                      Dialer(this, &Comm::ConnOpener::timeout));
            debugs(5, 3, HERE << "FD " << conn_->fd << " timeout " << connectTimeout_);
            commSetTimeout(conn_->fd, connectTimeout_, calls_.timeout_);
        }

        if (connStart_ == 0) {
            connStart_ = squid_curtime;
        }
    }

    tryConnectiog();
}

void
Comm::ConnOpener::tryConnecting()
{
    Must(conn_ != NULL);

    totalTries_++;

    switch (comm_connect_addr(conn_->fd, conn_->remote) ) {

    case COMM_INPROGRESS:
        // check for timeout FIRST.
        if(squid_curtime - connStart_ > connectTimeout_) {
            debugs(5, 5, HERE << "FD " << conn_->fd << ": * - ERR took too long already.");
            doneConnecting(COMM_TIMEOUT, errno);
            return;
        } else {
            debugs(5, 5, HERE << "FD " << conn_->fd << ": COMM_INPROGRESS");
            commSetSelect(conn_->fd, COMM_SELECT_WRITE, Comm::ConnOpener::ConnectRetry, this, 0);
        }
        break;

    case COMM_OK:
        debugs(5, 5, HERE << "FD " << conn_->fd << ": COMM_OK - connected");

        /*
         * stats.conn_open is used to account for the number of
         * connections that we have open to the peer, so we can limit
         * based on the max-conn option.  We need to increment here,
         * even if the connection may fail.
         */
        if (conn_->getPeer())
            conn_->getPeer()->stats.conn_open++;

        /* TODO: remove these fd_table accesses. But old code still depends on fd_table flags to
         *       indicate the state of a raw fd object being passed around.
         *       Also, legacy code still depends on comm_local_port() with no access to Comm::Connection
         *       when those are done comm_local_port can become one of our member functions to do the below.
         */
        fd_table[conn_->fd].flags.open = 1;
        conn_->local.SetPort(comm_local_port(conn_->fd));
        if (conn_->local.IsAnyAddr()) {
            conn_->local = fd_table[conn_->fd].local_addr;
        }

        if (host_ != NULL)
            ipcacheMarkGoodAddr(host_, conn_->remote);
        doneConnecting(COMM_OK, 0);
        break;

    default:
        debugs(5, 5, HERE "FD " << conn_->fd << ": * - try again");
        failRetries_++;
        if (host_ != NULL)
            ipcacheMarkBadAddr(host_, conn_->remote);
#if USE_ICMP
        if (Config.onoff.test_reachability)
            netdbDeleteAddrNetwork(conn_->remote);
#endif

        // check for timeout FIRST.
        if(squid_curtime - connStart_ > connectTimeout_) {
            debugs(5, 5, HERE << "FD " << conn_->fd << ": * - ERR took too long already.");
            doneConnecting(COMM_TIMEOUT, errno);
        } else if (failRetries_ < Config.connect_retries) {
            tryConnecting();
        } else {
            // send ERROR back to the upper layer.
            debugs(5, 5, HERE << "FD " << conn_->fd << ": * - ERR tried too many times already.");
            doneConnecting(COMM_ERR_CONNECT, errno);
        }
    }
}

/** Abort connection attempt.
 * Handles the case(s) when a partially setup connection gets closed early.
 */
void
Comm::ConnOpener::earlyAbort(const CommConnectCbParams &io)
{
    debugs(5, 3, HERE << "FD " << io.conn->fd);
    doneConnecting(COMM_ERR_CLOSING, io.xerrno); // NP: is closing or shutdown better?
}

/** Make an FD connection attempt.
 * Handles the case(s) when a partially setup connection gets closed early.
 */
void
Comm::ConnOpener::connect(const CommConnectCbParams &unused)
{
    tryConnecting();
}

/**
 * Handles the case(s) when a partially setup connection gets timed out.
 * NP: When commSetTimeout accepts generic CommCommonCbParams this can die.
 */
void
Comm::ConnOpener::timeout(const CommTimeoutCbParams &unused)
{
    tryConnecting();
}

/* Legacy Wrapper for the retry event after COMM_INPROGRESS
 * TODO: As soon as comm IO accepts Async calls we can use a ConnOpener::connect call
 */
void
Comm::ConnOpener::ConnectRetry(int fd, void *data)
{
    ConnOpener *cs = static_cast<Comm::ConnOpener *>(data);
    cs->tryConnecting();

    // see if its done and delete Comm::ConnOpener? comm Writes are not yet a Job call.
    // so the automatic cleanup on call completion does not seem to happen
    if (cs->doneAll());
        cs->deleteThis("Done after Comm::ConnOpener::ConnectRetry()");
}
