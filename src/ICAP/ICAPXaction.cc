/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "CommCalls.h"
#include "HttpMsg.h"
#include "ICAPXaction.h"
#include "ICAPConfig.h"
#include "TextException.h"
#include "pconn.h"
#include "fde.h"

static PconnPool *icapPconnPool = new PconnPool("ICAP Servers");


//CBDATA_CLASS_INIT(ICAPXaction);

ICAPXaction::ICAPXaction(const char *aTypeName, Adaptation::Initiator *anInitiator, ICAPServiceRep::Pointer &aService):
        AsyncJob(aTypeName),
        Adaptation::Initiate(aTypeName, anInitiator, aService.getRaw()),
        connection(-1),
        commBuf(NULL), commBufSize(0),
        commEof(false),
        reuseConnection(true),
        isRetriable(true),
        ignoreLastWrite(false),
        connector(NULL), reader(NULL), writer(NULL), closer(NULL)
{
    debugs(93,3, typeName << " constructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
}

ICAPXaction::~ICAPXaction()
{
    debugs(93,3, typeName << " destructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
}

ICAPServiceRep &
ICAPXaction::service()
{
    ICAPServiceRep *s = dynamic_cast<ICAPServiceRep*>(&Initiate::service());
    Must(s);
    return *s;
}

void ICAPXaction::disableRetries()
{
    debugs(93,5, typeName << (isRetriable ? " becomes" : " remains") <<
           " final" << status());
    isRetriable = false;
}

void ICAPXaction::start()
{
    Adaptation::Initiate::start();

    readBuf.init(SQUID_TCP_SO_RCVBUF, SQUID_TCP_SO_RCVBUF);
    commBuf = (char*)memAllocBuf(SQUID_TCP_SO_RCVBUF, &commBufSize);
    // make sure maximum readBuf space does not exceed commBuf size
    Must(static_cast<size_t>(readBuf.potentialSpaceSize()) <= commBufSize);
}

// TODO: obey service-specific, OPTIONS-reported connection limit
void ICAPXaction::openConnection()
{
    IpAddress client_addr;

    Must(connection < 0);

    const Adaptation::Service &s = service();

    if (!TheICAPConfig.reuse_connections)
        disableRetries(); // this will also safely drain pconn pool

    // TODO: check whether NULL domain is appropriate here
    connection = icapPconnPool->pop(s.cfg().host.termedBuf(), s.cfg().port, NULL, client_addr, isRetriable);
    if (connection >= 0) {
        debugs(93,3, HERE << "reused pconn FD " << connection);

        // fake the connect callback
        // TODO: can we sync call ICAPXaction::noteCommConnected here instead?
        typedef CommCbMemFunT<ICAPXaction, CommConnectCbParams> Dialer;
        Dialer dialer(this, &ICAPXaction::noteCommConnected);
	dialer.params.fd = connection;
        dialer.params.flag = COMM_OK;
        // fake other parameters by copying from the existing connection
        connector = asyncCall(93,3, "ICAPXaction::noteCommConnected", dialer);
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
    typedef CommCbMemFunT<ICAPXaction, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(93, 5, "ICAPXaction::noteCommTimedout",
                                      TimeoutDialer(this,&ICAPXaction::noteCommTimedout));

    commSetTimeout(connection, TheICAPConfig.connect_timeout(
                       service().cfg().bypass), timeoutCall);

    typedef CommCbMemFunT<ICAPXaction, CommCloseCbParams> CloseDialer;
    closer =  asyncCall(93, 5, "ICAPXaction::noteCommClosed",
                        CloseDialer(this,&ICAPXaction::noteCommClosed));
    comm_add_close_handler(connection, closer);

    typedef CommCbMemFunT<ICAPXaction, CommConnectCbParams> ConnectDialer;
    connector = asyncCall(93,3, "ICAPXaction::noteCommConnected",
                          ConnectDialer(this, &ICAPXaction::noteCommConnected));
    commConnectStart(connection, s.cfg().host.termedBuf(), s.cfg().port, connector);
}

/*
 * This event handler is necessary to work around the no-rentry policy
 * of ICAPXaction::callStart()
 */
#if 0
void
ICAPXaction::reusedConnection(void *data)
{
    debugs(93, 5, "ICAPXaction::reusedConnection");
    ICAPXaction *x = (ICAPXaction*)data;
    x->noteCommConnected(COMM_OK);
}
#endif

void ICAPXaction::closeConnection()
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
void ICAPXaction::noteCommConnected(const CommConnectCbParams &io)
{
    Must(connector != NULL);
    connector = NULL;

    if (io.flag != COMM_OK)
        dieOnConnectionFailure(); // throws

    fd_table[connection].noteUse(icapPconnPool);

    handleCommConnected();
}

void ICAPXaction::dieOnConnectionFailure()
{
    debugs(93, 2, HERE << typeName <<
           " failed to connect to " << service().cfg().uri);
    theService->noteFailure();
    throw TexcHere("cannot connect to the ICAP service");
}

void ICAPXaction::scheduleWrite(MemBuf &buf)
{
    // comm module will free the buffer
    typedef CommCbMemFunT<ICAPXaction, CommIoCbParams> Dialer;
    writer = asyncCall(93,3, "ICAPXaction::noteCommWrote",
                       Dialer(this, &ICAPXaction::noteCommWrote));

    comm_write_mbuf(connection, &buf, writer);
    updateTimeout();
}

void ICAPXaction::noteCommWrote(const CommIoCbParams &io)
{
    Must(writer != NULL);
    writer = NULL;

    if (ignoreLastWrite) {
        // a hack due to comm inability to cancel a pending write
        ignoreLastWrite = false;
        debugs(93, 7, HERE << "ignoring last write; status: " << io.flag);
    } else {
        Must(io.flag == COMM_OK);
        updateTimeout();
        handleCommWrote(io.size);
    }
}

// communication timeout with the ICAP service
void ICAPXaction::noteCommTimedout(const CommTimeoutCbParams &io)
{
    handleCommTimedout();
}

void ICAPXaction::handleCommTimedout()
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
void ICAPXaction::noteCommClosed(const CommCloseCbParams &io)
{
    closer = NULL;
    handleCommClosed();
}

void ICAPXaction::handleCommClosed()
{
    mustStop("ICAP service connection externally closed");
}

void ICAPXaction::callEnd()
{
    if (doneWithIo()) {
        debugs(93, 5, HERE << typeName << " done with I/O" << status());
        closeConnection();
    }
    Adaptation::Initiate::callEnd(); // may destroy us
}

bool ICAPXaction::doneAll() const
{
    return !connector && !reader && !writer && Adaptation::Initiate::doneAll();
}

void ICAPXaction::updateTimeout()
{
    if (reader != NULL || writer != NULL) {
        // restart the timeout before each I/O
        // XXX: why does Config.Timeout lacks a write timeout?
        // TODO: service bypass status may differ from that of a transaction
        typedef CommCbMemFunT<ICAPXaction, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer call =  asyncCall(93, 5, "ICAPXaction::noteCommTimedout",
                                             TimeoutDialer(this,&ICAPXaction::noteCommTimedout));

        commSetTimeout(connection,
                       TheICAPConfig.io_timeout(service().cfg().bypass), call);
    } else {
        // clear timeout when there is no I/O
        // Do we need a lifetime timeout?
        AsyncCall::Pointer call = NULL;
        commSetTimeout(connection, -1, call);
    }
}

void ICAPXaction::scheduleRead()
{
    Must(connection >= 0);
    Must(!reader);
    Must(readBuf.hasSpace());

    /*
     * See comments in ICAPXaction.h about why we use commBuf
     * here instead of reading directly into readBuf.buf.
     */
    typedef CommCbMemFunT<ICAPXaction, CommIoCbParams> Dialer;
    reader = asyncCall(93,3, "ICAPXaction::noteCommRead",
                       Dialer(this, &ICAPXaction::noteCommRead));

    comm_read(connection, commBuf, readBuf.spaceSize(), reader);
    updateTimeout();
}

// comm module read a portion of the ICAP response for us
void ICAPXaction::noteCommRead(const CommIoCbParams &io)
{
    Must(reader != NULL);
    reader = NULL;

    Must(io.flag == COMM_OK);
    Must(io.size >= 0);

    updateTimeout();

    debugs(93, 3, HERE << "read " << io.size << " bytes");

    /*
     * See comments in ICAPXaction.h about why we use commBuf
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

void ICAPXaction::cancelRead()
{
    if (reader != NULL) {
        comm_read_cancel(connection, reader);
        reader = NULL;
    }
}

bool ICAPXaction::parseHttpMsg(HttpMsg *msg)
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

bool ICAPXaction::mayReadMore() const
{
    return !doneReading() && // will read more data
           readBuf.hasSpace();  // have space for more data
}

bool ICAPXaction::doneReading() const
{
    return commEof;
}

bool ICAPXaction::doneWriting() const
{
    return !writer;
}

bool ICAPXaction::doneWithIo() const
{
    return connection >= 0 && // or we could still be waiting to open it
           !connector && !reader && !writer && // fast checks, some redundant
           doneReading() && doneWriting();
}

// initiator aborted
void ICAPXaction::noteInitiatorAborted()
{

    if (theInitiator) {
        clearInitiator();
        mustStop("initiator aborted");
    }

}

// This 'last chance' method is called before a 'done' transaction is deleted.
// It is wrong to call virtual methods from a destructor. Besides, this call
// indicates that the transaction will terminate as planned.
void ICAPXaction::swanSong()
{
    // kids should sing first and then call the parent method.

    closeConnection(); // TODO: rename because we do not always close

    if (!readBuf.isNull())
        readBuf.clean();

    if (commBuf)
        memFreeBuf(commBufSize, commBuf);

    if (theInitiator)
        tellQueryAborted(!isRetriable);

    Adaptation::Initiate::swanSong();
}

// returns a temporary string depicting transaction status, for debugging
const char *ICAPXaction::status() const
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

void ICAPXaction::fillPendingStatus(MemBuf &buf) const
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

void ICAPXaction::fillDoneStatus(MemBuf &buf) const
{
    if (connection >= 0 && commEof)
        buf.Printf("Comm(%d)", connection);

    if (stopReason != NULL)
        buf.Printf("Stopped");
}

bool ICAPXaction::fillVirginHttpHeader(MemBuf &buf) const
{
    return false;
}
