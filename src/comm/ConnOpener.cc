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
        connect_timeout(ctimeout),
        host(NULL),
        solo(c),
        callback(handler),
        total_tries(0),
        fail_retries(0),
        connstart(0)
{
    memset(&calls, 0, sizeof(calls));
}

Comm::ConnOpener::~ConnOpener()
{
    safe_free(host);
    solo = NULL;
    calls.earlyabort = NULL;
    calls.timeout = NULL;
}

bool
Comm::ConnOpener::doneAll() const
{
    // is the conn to be opened still waiting?
    if (solo != NULL) {
        debugs(5, 6, HERE << " Comm::ConnOpener::doneAll() ? NO. 'solo' is still set");
        return false;
    }

    // is the callback still to be called?
    if (callback != NULL) {
        debugs(5, 6, HERE << " Comm::ConnOpener::doneAll() ? NO. callback is still set");
        return false;
    }

    debugs(5, 6, HERE << " Comm::ConnOpener::doneAll() ? YES.");
    return true;
}

void
Comm::ConnOpener::swanSong()
{
    // cancel any event watchers
    if (calls.earlyabort != NULL) {
        calls.earlyabort->cancel("Comm::ConnOpener::swanSong");
        calls.earlyabort = NULL;
    }
    if (calls.timeout != NULL) {
        calls.timeout->cancel("Comm::ConnOpener::swanSong");
        calls.timeout = NULL;
    }

    // recover what we can from the job
    if (solo != NULL && solo->fd > -1) {
        // it never reached fully open, so abort the FD
        close(solo->fd);
        fd_table[solo->fd].flags.open = 0;
        // inform the caller
        callCallback(COMM_ERR_CONNECT, 0);
    }
}

void
Comm::ConnOpener::setHost(const char * new_host)
{
    // unset and erase if already set.
    if (host != NULL)
        safe_free(host);

    // set the new one if given.
    if (new_host != NULL)
        host = xstrdup(new_host);
}

const char *
Comm::ConnOpener::getHost() const
{
    return host;
}

void
Comm::ConnOpener::callCallback(comm_err_t status, int xerrno)
{
    /* remove handlers we don't want to happen anymore */
    if (solo != NULL && solo->fd > 0) {
        if (calls.earlyabort != NULL) {
            comm_remove_close_handler(solo->fd, calls.earlyabort);
            calls.earlyabort->cancel("Comm::ConnOpener completed.");
            calls.earlyabort = NULL;
        }
        if (calls.timeout != NULL) {
            commSetTimeout(solo->fd, -1, NULL, NULL);
            calls.timeout->cancel("Comm::ConnOpener completed.");
            calls.timeout = NULL;
        }
    }

    if (callback != NULL) {
        typedef CommConnectCbParams Params;
        Params &params = GetCommParams<Params>(callback);
        params.conn = solo;
        params.flag = status;
        params.xerrno = xerrno;
        ScheduleCallHere(callback);
        callback = NULL;
    }

    /* ensure cleared local state, we are done. */
    solo = NULL;

    assert(doneAll());
}

void
Comm::ConnOpener::start()
{
    Must(solo != NULL);

    /* handle connecting to one single path */
    if (solo->fd < 0) {
#if USE_IPV6
        /* outbound sockets have no need to be protocol agnostic. */
        if (solo->local.IsIPv6() && solo->local.IsIPv4()) {
            solo->local.SetIPv4();
        }
#endif
        solo->fd = comm_openex(SOCK_STREAM, IPPROTO_TCP, solo->local, solo->flags, solo->tos, host);
        if (solo->fd < 0) {
            callCallback(COMM_ERR_CONNECT, 0);
            return;
        }

        if (calls.earlyabort == NULL) {
            typedef CommCbMemFunT<Comm::ConnOpener, CommConnectCbParams> Dialer;
            calls.earlyabort = asyncCall(5, 4, "Comm::ConnOpener::earlyAbort",
                                         Dialer(this, &Comm::ConnOpener::earlyAbort));
        }
        comm_add_close_handler(solo->fd, calls.earlyabort);

        if (calls.timeout == NULL) {
            typedef CommCbMemFunT<Comm::ConnOpener, CommTimeoutCbParams> Dialer;
            calls.timeout = asyncCall(5, 4, "Comm::ConnOpener::timeout",
                                      Dialer(this, &Comm::ConnOpener::timeout));
        }
        debugs(5, 3, HERE << "FD " << solo->fd << " timeout " << connect_timeout);
        commSetTimeout(solo->fd, connect_timeout, calls.timeout);

        if (connstart == 0) {
            connstart = squid_curtime;
        }
    }

    total_tries++;

    switch (comm_connect_addr(solo->fd, solo->remote) ) {

    case COMM_INPROGRESS:
        // check for timeout FIRST.
        if(squid_curtime - connstart > connect_timeout) {
            debugs(5, 5, HERE << "FD " << solo->fd << ": * - ERR took too long already.");
            callCallback(COMM_TIMEOUT, errno);
            return;
        } else {
            debugs(5, 5, HERE << "FD " << solo->fd << ": COMM_INPROGRESS");
            commSetSelect(solo->fd, COMM_SELECT_WRITE, Comm::ConnOpener::ConnectRetry, this, 0);
        }
        break;

    case COMM_OK:
        debugs(5, 5, HERE << "FD " << solo->fd << ": COMM_OK - connected");

        /*
         * stats.conn_open is used to account for the number of
         * connections that we have open to the peer, so we can limit
         * based on the max-conn option.  We need to increment here,
         * even if the connection may fail.
         */
        if (solo->getPeer())
            solo->getPeer()->stats.conn_open++;

        /* TODO: remove these fd_table accesses. But old code still depends on fd_table flags to
         *       indicate the state of a raw fd object being passed around.
         *       Also, legacy code still depends on comm_local_port() with no access to Comm::Connection
         *       when those are done comm_local_port can become one of our member functions to do the below.
         */
        fd_table[solo->fd].flags.open = 1;
        solo->local.SetPort(comm_local_port(solo->fd));
        if (solo->local.IsAnyAddr()) {
            solo->local = fd_table[solo->fd].local_addr;
        }

        if (host != NULL)
            ipcacheMarkGoodAddr(host, solo->remote);
        callCallback(COMM_OK, 0);
        break;

    default:
        debugs(5, 5, HERE "FD " << solo->fd << ": * - try again");
        fail_retries++;
        if (host != NULL)
            ipcacheMarkBadAddr(host, solo->remote);
#if USE_ICMP
        if (Config.onoff.test_reachability)
            netdbDeleteAddrNetwork(solo->remote);
#endif

        // check for timeout FIRST.
        if(squid_curtime - connstart > connect_timeout) {
            debugs(5, 5, HERE << "FD " << solo->fd << ": * - ERR took too long already.");
            callCallback(COMM_TIMEOUT, errno);
        } else if (fail_retries < Config.connect_retries) {
            start();
        } else {
            // send ERROR back to the upper layer.
            debugs(5, 5, HERE << "FD " << solo->fd << ": * - ERR tried too many times already.");
            callCallback(COMM_ERR_CONNECT, errno);
        }
    }
}

void
Comm::ConnOpener::earlyAbort(const CommConnectCbParams &io)
{
    debugs(5, 3, HERE << "FD " << io.conn->fd);
    callCallback(COMM_ERR_CLOSING, io.xerrno); // NP: is closing or shutdown better?
}

void
Comm::ConnOpener::connect(const CommConnectCbParams &unused)
{
    start();
}

void
Comm::ConnOpener::timeout(const CommTimeoutCbParams &unused)
{
    start();
}

void
Comm::ConnOpener::ConnectRetry(int fd, void *data)
{
    ConnOpener *cs = static_cast<Comm::ConnOpener *>(data);
    cs->start();

    // see if its done and delete Comm::ConnOpener? comm Writes are not yet a Job call.
    // so the automatic cleanup on call completion does not seem to happen
    if (cs->doneAll());
        cs->deleteThis("Done after Comm::ConnOpener::ConnectRetry()");
}
