/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "HttpReply.h"
#include "ICAPXaction.h"
#include "ICAPClient.h"
#include "TextException.h"
#include "pconn.h"
#include "fde.h"

static PconnPool *icapPconnPool = new PconnPool("ICAP Servers");

/* comm module handlers (wrappers around corresponding ICAPXaction methods */

// TODO: Teach comm module to call object methods directly

//CBDATA_CLASS_INIT(ICAPXaction);

static
ICAPXaction &ICAPXaction_fromData(void *data)
{
    ICAPXaction *x = static_cast<ICAPXaction*>(data);
    assert(x);
    return *x;
}

static
void ICAPXaction_noteCommTimedout(int, void *data)
{
    ICAPXaction_fromData(data).noteCommTimedout();
}

static
void ICAPXaction_noteCommClosed(int, void *data)
{
    ICAPXaction_fromData(data).noteCommClosed();
}

static
void ICAPXaction_noteCommConnected(int, comm_err_t status, int xerrno, void *data)
{
    ICAPXaction_fromData(data).noteCommConnected(status);
}

static
void ICAPXaction_noteCommWrote(int, char *, size_t size, comm_err_t status, int xerrno, void *data)
{
    ICAPXaction_fromData(data).noteCommWrote(status, size);
}

static
void ICAPXaction_noteCommRead(int, char *, size_t size, comm_err_t status, int xerrno, void *data)
{
    debugs(93,3,HERE << data << " read returned " << size);
    ICAPXaction_fromData(data).noteCommRead(status, size);
}

ICAPXaction::ICAPXaction(const char *aTypeName):
        connection(-1),
        commBuf(NULL), commBufSize(0),
        commEof(false),
        reuseConnection(true),
        connector(NULL), reader(NULL), writer(NULL), closer(NULL),
        typeName(aTypeName),
        theService(NULL),
        inCall(NULL)
{
    debug(93,3)("%s constructed, this=%p\n", typeName, this);
    readBuf.init(SQUID_TCP_SO_RCVBUF, SQUID_TCP_SO_RCVBUF);
    commBuf = (char*)memAllocBuf(SQUID_TCP_SO_RCVBUF, &commBufSize);
    // make sure maximum readBuf space does not exceed commBuf size
    Must(static_cast<size_t>(readBuf.potentialSpaceSize()) <= commBufSize);
}

ICAPXaction::~ICAPXaction()
{
    debug(93,3)("%s destructing, this=%p\n", typeName, this);
    doStop();
    readBuf.clean();
    memFreeBuf(commBufSize, commBuf);
}

// TODO: obey service-specific, OPTIONS-reported connection limit
void ICAPXaction::openConnection()
{
    const ICAPServiceRep &s = service();
    // TODO: check whether NULL domain is appropriate here
    connection = icapPconnPool->pop(s.host.buf(), s.port, NULL);

    if (connection >= 0) {
        debugs(93,3, HERE << "reused pconn FD " << connection);
        eventAdd("ICAPXaction::reusedConnection",
                 reusedConnection,
                 this,
                 0.0,
                 0,
                 true);
        return;
    }

    if (connection < 0) {
        connection = comm_open(SOCK_STREAM, 0, getOutgoingAddr(NULL), 0,
                               COMM_NONBLOCKING, s.uri.buf());

        if (connection < 0)
            dieOnConnectionFailure(); // throws
    }

    debugs(93,3, typeName << " opens connection to " << s.host.buf() << ":" << s.port);

    commSetTimeout(connection, Config.Timeout.connect,
                   &ICAPXaction_noteCommTimedout, this);

    closer = &ICAPXaction_noteCommClosed;
    comm_add_close_handler(connection, closer, this);

    connector = &ICAPXaction_noteCommConnected;
    commConnectStart(connection, s.host.buf(), s.port, connector, this);
}

/*
 * This event handler is necessary to work around the no-rentry policy
 * of ICAPXaction::callStart()
 */
void
ICAPXaction::reusedConnection(void *data)
{
    debug(93,5)("ICAPXaction::reusedConnection\n");
    ICAPXaction *x = (ICAPXaction*)data;
    /*
     * XXX noteCommConnected Must()s that connector is set to something;
     */
    x->connector = &ICAPXaction_noteCommConnected;
    x->noteCommConnected(COMM_OK);
}

void ICAPXaction::closeConnection()
{
    if (connection >= 0) {

        if (closer) {
            comm_remove_close_handler(connection, closer, this);
            closer = NULL;
        }

        cancelRead(); // may not work

        if (reuseConnection && (writer || reader)) {
            debugs(93,5, HERE << "not reusing pconn due to pending I/O " << status());
            reuseConnection = false;
        }

        if (reuseConnection) {
            debugs(93,3, HERE << "pushing pconn " << status());
            commSetTimeout(connection, -1, NULL, NULL);
            icapPconnPool->push(connection, theService->host.buf(), theService->port, NULL);
        } else {
            debugs(93,3, HERE << "closing pconn " << status());
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
void ICAPXaction::noteCommConnected(comm_err_t commStatus)
{
    ICAPXaction_Enter(noteCommConnected);

    Must(connector);
    connector = NULL;

    if (commStatus != COMM_OK)
        dieOnConnectionFailure(); // throws

    fd_table[connection].noteUse(icapPconnPool);

    handleCommConnected();

    ICAPXaction_Exit();
}

void ICAPXaction::dieOnConnectionFailure() {
    theService->noteFailure();
    debugs(93,3, typeName << " failed to connect to the ICAP service at " <<
        service().uri);
    throw TexcHere("cannot connect to the ICAP service");
}

void ICAPXaction::scheduleWrite(MemBuf &buf)
{
    // comm module will free the buffer
    writer = &ICAPXaction_noteCommWrote;
    comm_write_mbuf(connection, &buf, writer, this);
    updateTimeout();
}

void ICAPXaction::noteCommWrote(comm_err_t commStatus, size_t size)
{
    ICAPXaction_Enter(noteCommWrote);

    Must(writer);
    writer = NULL;

    Must(commStatus == COMM_OK);

    updateTimeout();

    handleCommWrote(size);

    ICAPXaction_Exit();
}

// communication timeout with the ICAP service
void ICAPXaction::noteCommTimedout()
{
    ICAPXaction_Enter(noteCommTimedout);

    handleCommTimedout();

    ICAPXaction_Exit();
}

void ICAPXaction::handleCommTimedout()
{
    debugs(93, 0, HERE << "ICAP FD " << connection << " timeout to " << theService->methodStr() << " " << theService->uri.buf());
    reuseConnection = false;
    MemBuf mb;
    mb.init();

    if (fillVirginHttpHeader(mb)) {
        debugs(93, 0, HERE << "\tfor " << mb.content());
    }

    mustStop("connection with ICAP service timed out");
}

// unexpected connection close while talking to the ICAP service
void ICAPXaction::noteCommClosed()
{
    closer = NULL;
    ICAPXaction_Enter(noteCommClosed);

    handleCommClosed();

    ICAPXaction_Exit();
}

void ICAPXaction::handleCommClosed()
{
    mustStop("ICAP service connection externally closed");
}

bool ICAPXaction::done() const
{
    // stopReason, set in mustStop(), overwrites all other conditions
    return stopReason != NULL || doneAll();
}

bool ICAPXaction::doneAll() const
{
    return !connector && !reader && !writer;
}

void ICAPXaction::updateTimeout() {
    if (reader || writer) {
        // restart the timeout before each I/O
        // XXX: why does Config.Timeout lacks a write timeout?
        commSetTimeout(connection, Config.Timeout.read,
            &ICAPXaction_noteCommTimedout, this);
    } else {
        // clear timeout when there is no I/O
        // Do we need a lifetime timeout?
        commSetTimeout(connection, -1, NULL, NULL);
    }
}

void ICAPXaction::scheduleRead()
{
    Must(connection >= 0);
    Must(!reader);
    Must(readBuf.hasSpace());

    reader = &ICAPXaction_noteCommRead;
    /*
     * See comments in ICAPXaction.h about why we use commBuf
     * here instead of reading directly into readBuf.buf.
     */

    comm_read(connection, commBuf, readBuf.spaceSize(), reader, this);
    updateTimeout();
}

// comm module read a portion of the ICAP response for us
void ICAPXaction::noteCommRead(comm_err_t commStatus, size_t sz)
{
    ICAPXaction_Enter(noteCommRead);

    Must(reader);
    reader = NULL;

    Must(commStatus == COMM_OK);
    Must(sz >= 0);

    updateTimeout();

    debugs(93, 3, HERE << "read " << sz << " bytes");

    /*
     * See comments in ICAPXaction.h about why we use commBuf
     * here instead of reading directly into readBuf.buf.
     */

    if (sz > 0)
        readBuf.append(commBuf, sz);
    else
        commEof = true;

    handleCommRead(sz);

    ICAPXaction_Exit();
}

void ICAPXaction::cancelRead()
{
    if (reader) {
        // check callback presence because comm module removes
        // fdc_table[].read.callback after the actual I/O but
        // before we get the callback via a queued event.
        // These checks try to mimic the comm_read_cancel() assertions.

        if (comm_has_pending_read(connection) &&
                !comm_has_pending_read_callback(connection)) {
            comm_read_cancel(connection, reader, this);
            reader = NULL;
        }
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

void ICAPXaction::mustStop(const char *aReason)
{
    Must(inCall); // otherwise nobody will call doStop()
    Must(aReason);
    if (!stopReason) {
        stopReason = aReason;
        debugs(93, 5, typeName << " will stop, reason: " << stopReason);
    } else {
        debugs(93, 5, typeName << " will stop, another reason: " << aReason);
    }
}

// internal cleanup
void ICAPXaction::doStop()
{
    debugs(93, 5, typeName << "::doStop " << status());

    closeConnection(); // TODO: pconn support: close iff bad connection
}

void ICAPXaction::service(ICAPServiceRep::Pointer &aService)
{
    Must(!theService);
    Must(aService != NULL);
    theService = aService;
}

ICAPServiceRep &ICAPXaction::service()
{
    Must(theService != NULL);
    return *theService;
}

bool ICAPXaction::callStart(const char *method)
{
    debugs(93, 5, typeName << "::" << method << " called " << status());

    if (inCall) {
        // this may happen when we have bugs or when arguably buggy
        // comm interface calls us while we are closing the connection
        debugs(93, 5, typeName << "::" << inCall << " is in progress; " <<
               typeName << "::" << method << " cancels reentry.");
        return false;
    }

    inCall = method;
    return true;
}

void ICAPXaction::callException(const TextException &e)
{
    debugs(93, 4, typeName << "::" << inCall << " caught an exception: " <<
           e.message << ' ' << status());

    reuseConnection = false; // be conservative
    mustStop("exception");
}

void ICAPXaction::callEnd()
{
    if (done()) {
        debugs(93, 5, HERE << "ICAPXaction::" << inCall << " ends xaction " <<
               status());
        doStop(); // may delete us
        return;
    } else
    if (doneWithIo()) {
        debugs(93, 5, HERE << typeName << " done with I/O " << status());
        closeConnection();
    }

    debugs(93, 6, typeName << "::" << inCall << " ended " << status());
    inCall = NULL;
}

// returns a temporary string depicting transaction status, for debugging
const char *ICAPXaction::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append("[", 1);

    fillPendingStatus(buf);
    buf.append("/", 1);
    fillDoneStatus(buf);

    buf.append("]", 1);

    buf.terminate();

    return buf.content();
}

void ICAPXaction::fillPendingStatus(MemBuf &buf) const
{
    if (connection >= 0) {
        buf.Printf("Comm(%d", connection);

        if (writer)
            buf.append("w", 1);

        if (reader)
            buf.append("r", 1);

        buf.append(")", 1);
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
