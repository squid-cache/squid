/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/Xaction.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "err_detail_type.h"
#include "fde.h"
#include "FwdState.h"
#include "HttpMsg.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "icap_log.h"
#include "ipcache.h"
#include "Mem.h"
#include "pconn.h"
#include "SquidConfig.h"
#include "SquidTime.h"

//CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, Xaction);

Adaptation::Icap::Xaction::Xaction(const char *aTypeName, Adaptation::Icap::ServiceRep::Pointer &aService):
        AsyncJob(aTypeName),
        Adaptation::Initiate(aTypeName),
        icapRequest(NULL),
        icapReply(NULL),
        attempts(0),
        connection(NULL),
        theService(aService),
        commBuf(NULL), commBufSize(0),
        commEof(false),
        reuseConnection(true),
        isRetriable(true),
        isRepeatable(true),
        ignoreLastWrite(false),
        connector(NULL), reader(NULL), writer(NULL), closer(NULL),
        alep(new AccessLogEntry),
        al(*alep),
        cs(NULL)
{
    debugs(93,3, typeName << " constructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
    icapRequest = new HttpRequest;
    HTTPMSGLOCK(icapRequest);
    icap_tr_start = current_time;
}

Adaptation::Icap::Xaction::~Xaction()
{
    debugs(93,3, typeName << " destructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
    HTTPMSGUNLOCK(icapRequest);
}

Adaptation::Icap::ServiceRep &
Adaptation::Icap::Xaction::service()
{
    Must(theService != NULL);
    return *theService;
}

void Adaptation::Icap::Xaction::disableRetries()
{
    debugs(93,5, typeName << (isRetriable ? " from now on" : " still") <<
           " cannot be retried " << status());
    isRetriable = false;
}

void Adaptation::Icap::Xaction::disableRepeats(const char *reason)
{
    debugs(93,5, typeName << (isRepeatable ? " from now on" : " still") <<
           " cannot be repeated because " << reason << status());
    isRepeatable = false;
}

void Adaptation::Icap::Xaction::start()
{
    Adaptation::Initiate::start();

    readBuf.init(SQUID_TCP_SO_RCVBUF, SQUID_TCP_SO_RCVBUF);
    commBuf = (char*)memAllocBuf(SQUID_TCP_SO_RCVBUF, &commBufSize);
    // make sure maximum readBuf space does not exceed commBuf size
    Must(static_cast<size_t>(readBuf.potentialSpaceSize()) <= commBufSize);
}

static void
icapLookupDnsResults(const ipcache_addrs *ia, const DnsLookupDetails &, void *data)
{
    Adaptation::Icap::Xaction *xa = static_cast<Adaptation::Icap::Xaction *>(data);
    xa->dnsLookupDone(ia);
}

// TODO: obey service-specific, OPTIONS-reported connection limit
void
Adaptation::Icap::Xaction::openConnection()
{
    Must(!haveConnection());

    Adaptation::Icap::ServiceRep &s = service();

    if (!TheConfig.reuse_connections)
        disableRetries(); // this will also safely drain pconn pool

    bool wasReused = false;
    connection = s.getConnection(isRetriable, wasReused);

    if (wasReused && Comm::IsConnOpen(connection)) {
        // Set comm Close handler
        // fake the connect callback
        // TODO: can we sync call Adaptation::Icap::Xaction::noteCommConnected here instead?
        typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommConnectCbParams> Dialer;
        CbcPointer<Xaction> self(this);
        Dialer dialer(self, &Adaptation::Icap::Xaction::noteCommConnected);
        dialer.params.conn = connection;
        dialer.params.flag = COMM_OK;
        // fake other parameters by copying from the existing connection
        connector = asyncCall(93,3, "Adaptation::Icap::Xaction::noteCommConnected", dialer);
        ScheduleCallHere(connector);
        return;
    }

    disableRetries(); // we only retry pconn failures

    // Attempt to open a new connection...
    debugs(93,3, typeName << " opens connection to " << s.cfg().host.termedBuf() << ":" << s.cfg().port);

    // Locate the Service IP(s) to open
    ipcache_nbgethostbyname(s.cfg().host.termedBuf(), icapLookupDnsResults, this);
}

void
Adaptation::Icap::Xaction::dnsLookupDone(const ipcache_addrs *ia)
{
    Adaptation::Icap::ServiceRep &s = service();

    if (ia == NULL) {
        debugs(44, DBG_IMPORTANT, "ICAP: Unknown service host: " << s.cfg().host);

#if WHEN_IPCACHE_NBGETHOSTBYNAME_USES_ASYNC_CALLS
        dieOnConnectionFailure(); // throws
#else // take a step back into protected Async call dialing.
        // fake the connect callback
        typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommConnectCbParams> Dialer;
        CbcPointer<Xaction> self(this);
        Dialer dialer(self, &Adaptation::Icap::Xaction::noteCommConnected);
        dialer.params.conn = connection;
        dialer.params.flag = COMM_ERROR;
        // fake other parameters by copying from the existing connection
        connector = asyncCall(93,3, "Adaptation::Icap::Xaction::noteCommConnected", dialer);
        ScheduleCallHere(connector);
#endif
        return;
    }

    assert(ia->cur < ia->count);

    connection = new Comm::Connection;
    connection->remote = ia->in_addrs[ia->cur];
    connection->remote.port(s.cfg().port);
    getOutgoingAddress(NULL, connection);

    // TODO: service bypass status may differ from that of a transaction
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommConnectCbParams> ConnectDialer;
    connector = JobCallback(93,3, ConnectDialer, this, Adaptation::Icap::Xaction::noteCommConnected);
    cs = new Comm::ConnOpener(connection, connector, TheConfig.connect_timeout(service().cfg().bypass));
    cs->setHost(s.cfg().host.termedBuf());
    AsyncJob::Start(cs);
}

/*
 * This event handler is necessary to work around the no-rentry policy
 * of Adaptation::Icap::Xaction::callStart()
 */
#if 0
void
Adaptation::Icap::Xaction::reusedConnection(void *data)
{
    debugs(93, 5, HERE << "reused connection");
    Adaptation::Icap::Xaction *x = (Adaptation::Icap::Xaction*)data;
    x->noteCommConnected(COMM_OK);
}
#endif

void Adaptation::Icap::Xaction::closeConnection()
{
    if (haveConnection()) {

        if (closer != NULL) {
            comm_remove_close_handler(connection->fd, closer);
            closer = NULL;
        }

        cancelRead(); // may not work

        if (reuseConnection && !doneWithIo()) {
            //status() adds leading spaces.
            debugs(93,5, HERE << "not reusing pconn due to pending I/O" << status());
            reuseConnection = false;
        }

        if (reuseConnection)
            disableRetries();

        const bool reset = !reuseConnection &&
                           (al.icap.outcome == xoGone || al.icap.outcome == xoError);

        Adaptation::Icap::ServiceRep &s = service();
        s.putConnection(connection, reuseConnection, reset, status());

        writer = NULL;
        reader = NULL;
        connector = NULL;
        connection = NULL;
    }
}

// connection with the ICAP service established
void Adaptation::Icap::Xaction::noteCommConnected(const CommConnectCbParams &io)
{
    cs = NULL;

    if (io.flag == COMM_TIMEOUT) {
        handleCommTimedout();
        return;
    }

    Must(connector != NULL);
    connector = NULL;

    if (io.flag != COMM_OK)
        dieOnConnectionFailure(); // throws

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommTimedout",
                                      TimeoutDialer(this,&Adaptation::Icap::Xaction::noteCommTimedout));
    commSetConnTimeout(io.conn, TheConfig.connect_timeout(service().cfg().bypass), timeoutCall);

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommCloseCbParams> CloseDialer;
    closer =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommClosed",
                        CloseDialer(this,&Adaptation::Icap::Xaction::noteCommClosed));
    comm_add_close_handler(io.conn->fd, closer);

// ??    fd_table[io.conn->fd].noteUse(icapPconnPool);
    service().noteConnectionUse(connection);

    handleCommConnected();
}

void Adaptation::Icap::Xaction::dieOnConnectionFailure()
{
    debugs(93, 2, HERE << typeName <<
           " failed to connect to " << service().cfg().uri);
    service().noteConnectionFailed("failure");
    detailError(ERR_DETAIL_ICAP_XACT_START);
    throw TexcHere("cannot connect to the ICAP service");
}

void Adaptation::Icap::Xaction::scheduleWrite(MemBuf &buf)
{
    Must(haveConnection());

    // comm module will free the buffer
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommIoCbParams> Dialer;
    writer = JobCallback(93, 3,
                         Dialer, this, Adaptation::Icap::Xaction::noteCommWrote);

    Comm::Write(connection, &buf, writer);
    updateTimeout();
}

void Adaptation::Icap::Xaction::noteCommWrote(const CommIoCbParams &io)
{
    Must(writer != NULL);
    writer = NULL;

    if (ignoreLastWrite) {
        // a hack due to comm inability to cancel a pending write
        ignoreLastWrite = false;
        debugs(93, 7, HERE << "ignoring last write; status: " << io.flag);
    } else {
        Must(io.flag == COMM_OK);
        al.icap.bytesSent += io.size;
        updateTimeout();
        handleCommWrote(io.size);
    }
}

// communication timeout with the ICAP service
void Adaptation::Icap::Xaction::noteCommTimedout(const CommTimeoutCbParams &io)
{
    handleCommTimedout();
}

void Adaptation::Icap::Xaction::handleCommTimedout()
{
    debugs(93, 2, HERE << typeName << " failed: timeout with " <<
           theService->cfg().methodStr() << " " <<
           theService->cfg().uri << status());
    reuseConnection = false;
    const bool whileConnecting = connector != NULL;
    if (whileConnecting) {
        assert(!haveConnection());
        theService->noteConnectionFailed("timedout");
    } else
        closeConnection(); // so that late Comm callbacks do not disturb bypass
    throw TexcHere(whileConnecting ?
                   "timed out while connecting to the ICAP service" :
                   "timed out while talking to the ICAP service");
}

// unexpected connection close while talking to the ICAP service
void Adaptation::Icap::Xaction::noteCommClosed(const CommCloseCbParams &io)
{
    closer = NULL;
    handleCommClosed();
}

void Adaptation::Icap::Xaction::handleCommClosed()
{
    detailError(ERR_DETAIL_ICAP_XACT_CLOSE);
    mustStop("ICAP service connection externally closed");
}

void Adaptation::Icap::Xaction::callException(const std::exception  &e)
{
    setOutcome(xoError);
    service().noteFailure();
    Adaptation::Initiate::callException(e);
}

void Adaptation::Icap::Xaction::callEnd()
{
    if (doneWithIo()) {
        debugs(93, 5, HERE << typeName << " done with I/O" << status());
        closeConnection();
    }
    Adaptation::Initiate::callEnd(); // may destroy us
}

bool Adaptation::Icap::Xaction::doneAll() const
{
    return !connector && !reader && !writer && Adaptation::Initiate::doneAll();
}

void Adaptation::Icap::Xaction::updateTimeout()
{
    Must(haveConnection());

    if (reader != NULL || writer != NULL) {
        // restart the timeout before each I/O
        // XXX: why does Config.Timeout lacks a write timeout?
        // TODO: service bypass status may differ from that of a transaction
        typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer call = JobCallback(93, 5, TimeoutDialer, this, Adaptation::Icap::Xaction::noteCommTimedout);
        commSetConnTimeout(connection, TheConfig.io_timeout(service().cfg().bypass), call);
    } else {
        // clear timeout when there is no I/O
        // Do we need a lifetime timeout?
        commUnsetConnTimeout(connection);
    }
}

void Adaptation::Icap::Xaction::scheduleRead()
{
    Must(haveConnection());
    Must(!reader);
    Must(readBuf.hasSpace());

    /*
     * See comments in Adaptation::Icap::Xaction.h about why we use commBuf
     * here instead of reading directly into readBuf.buf.
     */
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommIoCbParams> Dialer;
    reader = JobCallback(93, 3,
                         Dialer, this, Adaptation::Icap::Xaction::noteCommRead);

    comm_read(connection, commBuf, readBuf.spaceSize(), reader);
    updateTimeout();
}

// comm module read a portion of the ICAP response for us
void Adaptation::Icap::Xaction::noteCommRead(const CommIoCbParams &io)
{
    Must(reader != NULL);
    reader = NULL;

    Must(io.flag == COMM_OK);

    if (!io.size) {
        commEof = true;
        reuseConnection = false;

        // detect a pconn race condition: eof on the first pconn read
        if (!al.icap.bytesRead && retriable()) {
            setOutcome(xoRace);
            mustStop("pconn race");
            return;
        }
    } else {

        al.icap.bytesRead+=io.size;

        updateTimeout();

        debugs(93, 3, HERE << "read " << io.size << " bytes");

        /*
         * See comments in Adaptation::Icap::Xaction.h about why we use commBuf
         * here instead of reading directly into readBuf.buf.
         */

        readBuf.append(commBuf, io.size);
        disableRetries(); // because pconn did not fail
    }

    handleCommRead(io.size);
}

void Adaptation::Icap::Xaction::cancelRead()
{
    if (reader != NULL) {
        Must(haveConnection());
        comm_read_cancel(connection->fd, reader);
        reader = NULL;
    }
}

bool Adaptation::Icap::Xaction::parseHttpMsg(HttpMsg *msg)
{
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " head bytes to parse");

    Http::StatusCode error = Http::scNone;
    const bool parsed = msg->parse(&readBuf, commEof, &error);
    Must(parsed || !error); // success or need more data

    if (!parsed) {	// need more data
        Must(mayReadMore());
        msg->reset();
        return false;
    }

    readBuf.consume(msg->hdr_sz);
    return true;
}

bool Adaptation::Icap::Xaction::mayReadMore() const
{
    return !doneReading() && // will read more data
           readBuf.hasSpace();  // have space for more data
}

bool Adaptation::Icap::Xaction::doneReading() const
{
    return commEof;
}

bool Adaptation::Icap::Xaction::doneWriting() const
{
    return !writer;
}

bool Adaptation::Icap::Xaction::doneWithIo() const
{
    return haveConnection() &&
           !connector && !reader && !writer && // fast checks, some redundant
           doneReading() && doneWriting();
}

bool Adaptation::Icap::Xaction::haveConnection() const
{
    return connection != NULL && connection->isOpen();
}

// initiator aborted
void Adaptation::Icap::Xaction::noteInitiatorAborted()
{

    if (theInitiator.set()) {
        debugs(93,4, HERE << "Initiator gone before ICAP transaction ended");
        clearInitiator();
        detailError(ERR_DETAIL_ICAP_INIT_GONE);
        setOutcome(xoGone);
        mustStop("initiator aborted");
    }

}

void Adaptation::Icap::Xaction::setOutcome(const Adaptation::Icap::XactOutcome &xo)
{
    if (al.icap.outcome != xoUnknown) {
        debugs(93, 3, HERE << "Warning: reseting outcome: from " <<
               al.icap.outcome << " to " << xo);
    } else {
        debugs(93, 4, HERE << xo);
    }
    al.icap.outcome = xo;
}

// This 'last chance' method is called before a 'done' transaction is deleted.
// It is wrong to call virtual methods from a destructor. Besides, this call
// indicates that the transaction will terminate as planned.
void Adaptation::Icap::Xaction::swanSong()
{
    // kids should sing first and then call the parent method.
    if (cs) {
        debugs(93,6, HERE << id << " about to notify ConnOpener!");
        CallJobHere(93, 3, cs, Comm::ConnOpener, noteAbort);
        cs = NULL;
        service().noteConnectionFailed("abort");
    }

    closeConnection(); // TODO: rename because we do not always close

    if (!readBuf.isNull())
        readBuf.clean();

    if (commBuf)
        memFreeBuf(commBufSize, commBuf);

    tellQueryAborted();

    maybeLog();

    Adaptation::Initiate::swanSong();
}

void Adaptation::Icap::Xaction::tellQueryAborted()
{
    if (theInitiator.set()) {
        Adaptation::Icap::XactAbortInfo abortInfo(icapRequest, icapReply.getRaw(),
                retriable(), repeatable());
        Launcher *launcher = dynamic_cast<Launcher*>(theInitiator.get());
        // launcher may be nil if initiator is invalid
        CallJobHere1(91,5, CbcPointer<Launcher>(launcher),
                     Launcher, noteXactAbort, abortInfo);
        clearInitiator();
    }
}

void Adaptation::Icap::Xaction::maybeLog()
{
    if (IcapLogfileStatus == LOG_ENABLE) {
        finalizeLogInfo();
        icapLogLog(alep);
    }
}

void Adaptation::Icap::Xaction::finalizeLogInfo()
{
    //prepare log data
    al.icp.opcode = ICP_INVALID;

    const Adaptation::Icap::ServiceRep &s = service();
    al.icap.hostAddr = s.cfg().host.termedBuf();
    al.icap.serviceName = s.cfg().key;
    al.icap.reqUri = s.cfg().uri;

    al.icap.ioTime = tvSubMsec(icap_tio_start, icap_tio_finish);
    al.icap.trTime = tvSubMsec(icap_tr_start, current_time);

    al.icap.request = icapRequest;
    HTTPMSGLOCK(al.icap.request);
    if (icapReply != NULL) {
        al.icap.reply = icapReply.getRaw();
        HTTPMSGLOCK(al.icap.reply);
        al.icap.resStatus = icapReply->sline.status();
    }
}

// returns a temporary string depicting transaction status, for debugging
const char *Adaptation::Icap::Xaction::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);

    fillPendingStatus(buf);
    buf.append("/", 1);
    fillDoneStatus(buf);

    buf.Printf(" %s%u]", id.Prefix, id.value);

    buf.terminate();

    return buf.content();
}

void Adaptation::Icap::Xaction::fillPendingStatus(MemBuf &buf) const
{
    if (haveConnection()) {
        buf.Printf("FD %d", connection->fd);

        if (writer != NULL)
            buf.append("w", 1);

        if (reader != NULL)
            buf.append("r", 1);

        buf.append(";", 1);
    }
}

void Adaptation::Icap::Xaction::fillDoneStatus(MemBuf &buf) const
{
    if (haveConnection() && commEof)
        buf.Printf("Comm(%d)", connection->fd);

    if (stopReason != NULL)
        buf.Printf("Stopped");
}

bool Adaptation::Icap::Xaction::fillVirginHttpHeader(MemBuf &buf) const
{
    return false;
}
