#include "config.h"
#include "comm/ConnOpener.h"
#include "comm/Connection.h"
#include "comm.h"
#include "CommCalls.h"
#include "fde.h"
#include "icmp/net_db.h"
#include "SquidTime.h"

CBDATA_CLASS_INIT(ConnOpener);

ConnOpener::ConnOpener(Comm::ConnectionPointer &c, AsyncCall::Pointer handler) :
        AsyncJob("ConnOpener"),
        connect_timeout(Config.Timeout.connect),
        host(NULL),
        solo(c),
        callback(handler),
        total_tries(0),
        fail_retries(0),
        connstart(0)
{}

ConnOpener::~ConnOpener()
{
    safe_free(host);
    solo = NULL;
}

void
ConnOpener::setHost(const char * new_host)
{
    // unset and erase if already set.
    if (host != NULL)
        safe_free(host);

    // set the new one if given.
    if (new_host != NULL)
        host = xstrdup(new_host);
}

const char *
ConnOpener::getHost() const
{
    return host;
}

void
ConnOpener::callCallback(comm_err_t status, int xerrno)
{
    /* remove handlers we don't want to happen now */
    comm_remove_close_handler(solo->fd, ConnOpener::EarlyAbort, this);
    commSetTimeout(solo->fd, -1, NULL, NULL);

    typedef CommConnectCbParams Params;
    Params &params = GetCommParams<Params>(callback);
    params.conn = solo;
    params.flag = status;
    params.xerrno = xerrno;
    ScheduleCallHere(callback);

    callback = NULL;
    delete this;
}

void
ConnOpener::start()
{
    /* handle connecting to one single path */
    if (solo->fd < 0) {
#if USE_IPV6
        /* outbound sockets have no need to be protocol agnostic. */
        if (solo->local.IsIPv6() && solo->local.IsIPv4()) {
            solo->local.SetIPv4();
        }
#endif
        solo->fd = comm_openex(SOCK_STREAM, IPPROTO_TCP, solo->local, solo->flags, solo->tos, host);
        if (solo->fd <= 0) {
            callCallback(COMM_ERR_CONNECT, 0);
            return;
        }

        AsyncCall::Pointer ea_call = commCbCall(5,4, "ConnOpener::EarlyAbort",
                                                CommCloseCbPtrFun(ConnOpener::EarlyAbort, this));
        comm_add_close_handler(solo->fd, ea_call);

        AsyncCall::Pointer timeout_call = commCbCall(5,4, "ConnOpener::ConnectTimeout",
                                                     CommTimeoutCbPtrFun(ConnOpener::ConnectTimeout, this));
        debugs(5, 3, HERE << "FD " << solo->fd << " timeout " << connect_timeout);
        commSetTimeout(solo->fd, connect_timeout, timeout_call);

        if (connstart == 0) {
            connstart = squid_curtime;
        }
    }

    total_tries++;

    switch (comm_connect_addr(solo->fd, solo->remote) ) {

    case COMM_INPROGRESS:
        debugs(5, 5, HERE << "FD " << solo->fd << ": COMM_INPROGRESS");
        commSetSelect(solo->fd, COMM_SELECT_WRITE, ConnOpener::ConnectRetry, this, 0);
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
         */
        fd_table[solo->fd].flags.open = 1;
        solo->local.SetPort(comm_local_port(solo->fd));

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
ConnOpener::EarlyAbort(int fd, void *data)
{
    ConnOpener *cs = static_cast<ConnOpener *>(data);
    debugs(5, 3, HERE << "FD " << fd);
    cs->callCallback(COMM_ERR_CLOSING, errno); // NP: is closing or shutdown better?

    /* TODO split cases:
     * remote end rejecting the connection is normal and one of the other paths may be taken.
     * squid shutting down or forcing abort on the connection attempt(s) are the only real fatal cases.
     * we may need separate error codes to send back for these two.
     */
}

void
ConnOpener::Connect(void *data)
{
    ConnOpener *cs = static_cast<ConnOpener *>(data);
    cs->start();
}

void
ConnOpener::ConnectRetry(int fd, void *data)
{
    ConnOpener *cs = static_cast<ConnOpener *>(data);
    cs->start();
}

void
ConnOpener::ConnectTimeout(int fd, void *data)
{
    ConnOpener *cs = static_cast<ConnOpener *>(data);
    cs->start();
}

