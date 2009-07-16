/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "CommCalls.h"
#include "HttpMsg.h"
#include "adaptation/icap/Xaction.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/Config.h"
#include "TextException.h"
#include "pconn.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "acl/FilledChecklist.h"
#include "icap_log.h"
#include "fde.h"
#include "SquidTime.h"

static PconnPool *icapPconnPool = new PconnPool("ICAP Servers");


//CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, Xaction);

Adaptation::Icap::Xaction::Xaction(const char *aTypeName, Adaptation::Initiator *anInitiator, Adaptation::Icap::ServiceRep::Pointer &aService):
        AsyncJob(aTypeName),
        Adaptation::Initiate(aTypeName, anInitiator),
        icapRequest(NULL),
        icapReply(NULL),
        attempts(0),
        connection(-1),
        theService(aService),
        commBuf(NULL), commBufSize(0),
        commEof(false),
        reuseConnection(true),
        isRetriable(true),
        isRepeatable(true),
        ignoreLastWrite(false),
        connector(NULL), reader(NULL), writer(NULL), closer(NULL)
{
    debugs(93,3, typeName << " constructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
    icapRequest = HTTPMSGLOCK(new HttpRequest);
    icap_tr_start = current_time;
}

Adaptation::Icap::Xaction::~Xaction()
{
    debugs(93,3, typeName << " destructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
    HTTPMSGUNLOCK(icapRequest);
    HTTPMSGUNLOCK(icapReply);
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

// TODO: obey service-specific, OPTIONS-reported connection limit
void Adaptation::Icap::Xaction::openConnection()
{
    IpAddress client_addr;

    Must(connection < 0);

    const Adaptation::Service &s = service();

    if (!TheConfig.reuse_connections)
        disableRetries(); // this will also safely drain pconn pool

    // TODO: check whether NULL domain is appropriate here
    connection = icapPconnPool->pop(s.cfg().host.termedBuf(), s.cfg().port, NULL, client_addr, isRetriable);
    if (connection >= 0) {
        debugs(93,3, HERE << "reused pconn FD " << connection);

        // fake the connect callback
        // TODO: can we sync call Adaptation::Icap::Xaction::noteCommConnected here instead?
        typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommConnectCbParams> Dialer;
        Dialer dialer(this, &Adaptation::Icap::Xaction::noteCommConnected);
        dialer.params.fd = connection;
        dialer.params.flag = COMM_OK;
        // fake other parameters by copying from the existing connection
        connector = asyncCall(93,3, "Adaptation::Icap::Xaction::noteCommConnected", dialer);
        ScheduleCallHere(connector);
        return;
    }

    disableRetries(); // we only retry pconn failures

    IpAddress outgoing;
    connection = comm_open(SOCK_STREAM, 0, outgoing,
                           COMM_NONBLOCKING, s.cfg().uri.termedBuf());

    if (connection < 0)
        dieOnConnectionFailure(); // throws

    debugs(93,3, typeName << " opens connection to " << s.cfg().host << ":" << s.cfg().port);

    // TODO: service bypass status may differ from that of a transaction
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommTimedout",
                                      TimeoutDialer(this,&Adaptation::Icap::Xaction::noteCommTimedout));

    commSetTimeout(connection, TheConfig.connect_timeout(
                       service().cfg().bypass), timeoutCall);

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommCloseCbParams> CloseDialer;
    closer =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommClosed",
                        CloseDialer(this,&Adaptation::Icap::Xaction::noteCommClosed));
    comm_add_close_handler(connection, closer);

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommConnectCbParams> ConnectDialer;
    connector = asyncCall(93,3, "Adaptation::Icap::Xaction::noteCommConnected",
                          ConnectDialer(this, &Adaptation::Icap::Xaction::noteCommConnected));
    commConnectStart(connection, s.cfg().host.termedBuf(), s.cfg().port, connector);
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
    if (connection >= 0) {

        if (closer != NULL) {
            comm_remove_close_handler(connection, closer);
            closer = NULL;
        }

        cancelRead(); // may not work

        if (reuseConnection && !doneWithIo()) {
            //status() adds leading spaces.
            debugs(93,5, HERE << "not reusing pconn due to pending I/O" << status());
            reuseConnection = false;
        }

        if (reuseConnection) {
            IpAddress client_addr;
            //status() adds leading spaces.
            debugs(93,3, HERE << "pushing pconn" << status());
            AsyncCall::Pointer call = NULL;
            commSetTimeout(connection, -1, call);
            icapPconnPool->push(connection, theService->cfg().host.termedBuf(),
                                theService->cfg().port, NULL, client_addr);
            disableRetries();
        } else {
            //status() adds leading spaces.
            debugs(93,3, HERE << "closing pconn" << status());
            // comm_close will clear timeout
            comm_close(connection);
        }

        writer = NULL;
        reader = NULL;
        connector = NULL;
        connection = -1;
    }
}

// connection with the ICAP service established
void Adaptation::Icap::Xaction::noteCommConnected(const CommConnectCbParams &io)
{
    Must(connector != NULL);
    connector = NULL;

    if (io.flag != COMM_OK)
        dieOnConnectionFailure(); // throws

    fd_table[connection].noteUse(icapPconnPool);

    handleCommConnected();
}

void Adaptation::Icap::Xaction::dieOnConnectionFailure()
{
    debugs(93, 2, HERE << typeName <<
           " failed to connect to " << service().cfg().uri);
    theService->noteFailure();
    throw TexcHere("cannot connect to the ICAP service");
}

void Adaptation::Icap::Xaction::scheduleWrite(MemBuf &buf)
{
    // comm module will free the buffer
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommIoCbParams> Dialer;
    writer = asyncCall(93,3, "Adaptation::Icap::Xaction::noteCommWrote",
                       Dialer(this, &Adaptation::Icap::Xaction::noteCommWrote));

    comm_write_mbuf(connection, &buf, writer);
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
    service().noteFailure();

    throw TexcHere(connector != NULL ?
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
    mustStop("ICAP service connection externally closed");
}

void Adaptation::Icap::Xaction::callException(const std::exception  &e)
{
    setOutcome(xoError);
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
    if (reader != NULL || writer != NULL) {
        // restart the timeout before each I/O
        // XXX: why does Config.Timeout lacks a write timeout?
        // TODO: service bypass status may differ from that of a transaction
        typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer call =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommTimedout",
                                             TimeoutDialer(this,&Adaptation::Icap::Xaction::noteCommTimedout));

        commSetTimeout(connection,
                       TheConfig.io_timeout(service().cfg().bypass), call);
    } else {
        // clear timeout when there is no I/O
        // Do we need a lifetime timeout?
        AsyncCall::Pointer call = NULL;
        commSetTimeout(connection, -1, call);
    }
}

void Adaptation::Icap::Xaction::scheduleRead()
{
    Must(connection >= 0);
    Must(!reader);
    Must(readBuf.hasSpace());

    /*
     * See comments in Adaptation::Icap::Xaction.h about why we use commBuf
     * here instead of reading directly into readBuf.buf.
     */
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommIoCbParams> Dialer;
    reader = asyncCall(93,3, "Adaptation::Icap::Xaction::noteCommRead",
                       Dialer(this, &Adaptation::Icap::Xaction::noteCommRead));

    comm_read(connection, commBuf, readBuf.spaceSize(), reader);
    updateTimeout();
}

// comm module read a portion of the ICAP response for us
void Adaptation::Icap::Xaction::noteCommRead(const CommIoCbParams &io)
{
    Must(reader != NULL);
    reader = NULL;

    Must(io.flag == COMM_OK);
    Must(io.size >= 0);

    al.icap.bytesRead+=io.size;

    updateTimeout();

    debugs(93, 3, HERE << "read " << io.size << " bytes");

    /*
     * See comments in Adaptation::Icap::Xaction.h about why we use commBuf
     * here instead of reading directly into readBuf.buf.
     */

    if (io.size > 0) {
        readBuf.append(commBuf, io.size);
        disableRetries(); // because pconn did not fail
    } else {
        reuseConnection = false;
        commEof = true;
    }

    handleCommRead(io.size);
}

void Adaptation::Icap::Xaction::cancelRead()
{
    if (reader != NULL) {
        comm_read_cancel(connection, reader);
        reader = NULL;
    }
}

bool Adaptation::Icap::Xaction::parseHttpMsg(HttpMsg *msg)
{
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " head bytes to parse");

    http_status error = HTTP_STATUS_NONE;
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
    return connection >= 0 && // or we could still be waiting to open it
           !connector && !reader && !writer && // fast checks, some redundant
           doneReading() && doneWriting();
}

// initiator aborted
void Adaptation::Icap::Xaction::noteInitiatorAborted()
{

    if (theInitiator) {
        clearInitiator();
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

    closeConnection(); // TODO: rename because we do not always close

    if (!readBuf.isNull())
        readBuf.clean();

    if (commBuf)
        memFreeBuf(commBufSize, commBuf);

    if (theInitiator)
        tellQueryAborted();

    maybeLog();

    Adaptation::Initiate::swanSong();
}

void Adaptation::Icap::Xaction::tellQueryAborted() {
    Adaptation::Icap::Launcher *l = dynamic_cast<Adaptation::Icap::Launcher*>(theInitiator.ptr());
    Adaptation::Icap::XactAbortInfo abortInfo(icapRequest, icapReply, retriable(), repeatable());
    CallJob(91, 5, __FILE__, __LINE__, 
            "Adaptation::Icap::Launcher::noteXactAbort",
            XactAbortCall(l, &Adaptation::Icap::Launcher::noteXactAbort, abortInfo) );
    clearInitiator();
}


void Adaptation::Icap::Xaction::maybeLog() {
    if(IcapLogfileStatus == LOG_ENABLE)
    {
        ACLChecklist *checklist = new ACLFilledChecklist(::Config.accessList.icap, al.request, dash_str);
        if (!::Config.accessList.icap || checklist->fastCheck()) {
            finalizeLogInfo();
            icapLogLog(&al, checklist);
        }
        accessLogFreeMemory(&al);
        delete checklist;
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

    al.icap.request = HTTPMSGLOCK(icapRequest);
    if (icapReply) {
        al.icap.reply = HTTPMSGLOCK(icapReply);
        al.icap.resStatus = icapReply->sline.status;
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

    buf.Printf(" icapx%d]", id);

    buf.terminate();

    return buf.content();
}

void Adaptation::Icap::Xaction::fillPendingStatus(MemBuf &buf) const
{
    if (connection >= 0) {
        buf.Printf("FD %d", connection);

        if (writer != NULL)
            buf.append("w", 1);

        if (reader != NULL)
            buf.append("r", 1);

        buf.append(";", 1);
    }
}

void Adaptation::Icap::Xaction::fillDoneStatus(MemBuf &buf) const
{
    if (connection >= 0 && commEof)
        buf.Printf("Comm(%d)", connection);

    if (stopReason != NULL)
        buf.Printf("Stopped");
}

bool Adaptation::Icap::Xaction::fillVirginHttpHeader(MemBuf &buf) const
{
    return false;
}
