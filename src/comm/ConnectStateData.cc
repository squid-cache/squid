#include "config.h"
#include "comm/ConnectStateData.h"
#include "comm.h"
#include "CommCalls.h"
#include "icmp/net_db.h"
#include "SquidTime.h"

CBDATA_CLASS_INIT(ConnectStateData);

ConnectStateData::ConnectStateData(Vector<Comm::Connection*> *paths, AsyncCall::Pointer handler) :
        host(NULL),
        connect_timeout(Config.Timeout.connect),
        paths(paths),
        solo(NULL),
        callback(handler),
        total_tries(0),
        fail_retries(0),
        connstart(0)
{}

ConnectStateData::ConnectStateData(Comm::Connection *c, AsyncCall::Pointer handler) :
        host(NULL),
        connect_timeout(Config.Timeout.connect),
        paths(paths),
        solo(c),
        callback(handler),
        total_tries(0),
        fail_retries(0),
        connstart(0)
{}

void *
ConnectStateData::operator new(size_t size)
{
    CBDATA_INIT_TYPE(ConnectStateData);
    return cbdataAlloc(ConnectStateData);
}

void
ConnectStateData::operator delete(void *address)
{
    cbdataFree(address);
}

void
ConnectStateData::callCallback(comm_err_t status, int xerrno)
{
    assert(paths != NULL);

    int fd = -1;
    if (paths->size() > 0) {
        fd = (*paths)[0]->fd;
        debugs(5, 3, HERE << "FD " << fd);
        comm_remove_close_handler(fd, ConnectStateData::EarlyAbort, this);
        commSetTimeout(fd, -1, NULL, NULL);
    }

    typedef CommConnectCbParams Params;
    Params &params = GetCommParams<Params>(callback);
    if (solo != NULL) {
        params.conn = solo;
    } else {
        params.paths = paths;
        if (paths->size() > 0)
            params.conn = (*paths)[0];
    }
    params.flag = status;
    params.xerrno = xerrno;
    ScheduleCallHere(callback);

    callback = NULL;
    safe_free(host);
    delete this;
}

void
ConnectStateData::connect()
{
    Comm::Connection *active;

    /* handle connecting to one single path */
    /* mainly used by components other than forwarding */

    /* handle connecting to one of multiple paths */
    /* mainly used by forwarding */

    if (solo) {
        active = solo;
    } else if (paths) {
        Vector<Comm::Connection*>::iterator i = paths->begin();

        if (connstart == 0) {
            connstart = squid_curtime;
        }

        /* find some socket we can use. will also bind the local address to it if needed. */
        while(paths->size() > 0 && (*i)->fd <= 0) {
#if USE_IPV6
            /* outbound sockets have no need to be protocol agnostic. */
            if ((*i)->local.IsIPv6() && (*i)->local.IsIPv4()) {
                (*i)->local.SetIPv4();
            }
#endif
            (*i)->fd = comm_openex(SOCK_STREAM, IPPROTO_TCP, (*i)->local, (*i)->flags, (*i)->tos, host);
            if ((*i)->fd <= 0) {
                debugs(5 , 2, HERE << "Unable to connect " << (*i)->local << " -> " << (*i)->remote << " for " << host);
                paths->shift();
                i = paths->begin();
            }
            // else success will terminate the loop with: i->fd >0
        }

        /* we have nowhere left to try connecting */
        if (paths->size() < 1) {
            callCallback(COMM_ERR_CONNECT, 0);
            return;
        }

        active = (*i);
    }

    total_tries++;

    switch (comm_connect_addr(active->fd, active->remote) ) {

    case COMM_INPROGRESS:
        debugs(5, 5, HERE << "FD " << active->fd << ": COMM_INPROGRESS");
        commSetSelect(active->fd, COMM_SELECT_WRITE, ConnectStateData::ConnectRetry, this, 0);
        break;

    case COMM_OK:
        debugs(5, 5, HERE << "FD " << active->fd << ": COMM_OK - connected");

    /*
     * stats.conn_open is used to account for the number of
     * connections that we have open to the peer, so we can limit
     * based on the max-conn option.  We need to increment here,
     * even if the connection may fail.
     */
        if (active->_peer)
            active->_peer->stats.conn_open++;

        ipcacheMarkGoodAddr(host, active->remote);
        callCallback(COMM_OK, 0);
        break;

    default:
        debugs(5, 5, HERE "FD " << active->fd << ": * - try again");
        fail_retries++;
        ipcacheMarkBadAddr(host, active->remote);

#if USE_ICMP
        if (Config.onoff.test_reachability)
            netdbDeleteAddrNetwork(active->remote);
#endif

        // TODO: do the re-try logic with some sane bounds for handling many paths and retries.
        if (fail_retries < Config.retry.maxtries)
            eventAdd("ConnectStateData::Connect", ConnectStateData::Connect, this, 0.5, 0);
        else if(squid_curtime - connstart > connect_timeout) {
            debugs(5, 5, HERE << "FD " << active->fd << ": * - ERR took too long already.");
            callCallback(COMM_TIMEOUT, errno);
        } else if (paths && paths->size() > 0) {
            paths->shift();
            fail_retries = 0;
            eventAdd("ConnectStateData::Connect", ConnectStateData::Connect, this, 0.0, 0);
        } else {
            debugs(5, 5, HERE << "FD " << active->fd << ": * - ERR tried too many times already.");
            callCallback(COMM_ERR_CONNECT, errno);
        }
    }
}

void
ConnectStateData::EarlyAbort(int fd, void *data)
{
    ConnectStateData *cs = static_cast<ConnectStateData *>(data);
    debugs(5, 3, HERE << "FD " << fd);
    cs->callCallback(COMM_ERR_CLOSING, errno); // NP: is closing or shutdown better?

    /* TODO split cases:
     * remote end rejecting the connection is normal and one of the other paths may be taken.
     * squid shutting down or forcing abort on the connection attempt(s) are the only real fatal cases.
     */
}
