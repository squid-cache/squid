/*
 * DEBUG: section 09    File Transfer Protocol (FTP)
 *
 */

#include "squid.h"

#include "FtpGatewayServer.h"
#include "FtpServer.h"
#include "HttpHdrCc.h"
#include "HttpRequest.h"
#include "Server.h"
#include "SquidTime.h"
#include "Store.h"
#include "client_side.h"
#include "wordlist.h"

namespace Ftp {

namespace Gateway {

class ServerStateData: public Ftp::ServerStateData
{
public:
    ServerStateData(FwdState *const fwdState);
    ~ServerStateData();

    virtual void processReplyBody();

protected:
    virtual void start();

    ConnStateData::FtpState clientState() const;
    void clientState(ConnStateData::FtpState s) const;
    virtual void failed(err_type error = ERR_NONE, int xerrno = 0);
    virtual void failedErrorMessage(err_type error, int xerrno);
    virtual void handleControlReply();
    virtual void handleRequestBodyProducerAborted();
    virtual bool doneWithServer() const;
    void forwardReply();
    void forwardError(err_type error = ERR_NONE, int xerrno = 0);
    HttpReply *createHttpReply(const Http::StatusCode httpStatus, const int clen = 0);
    void handleDataRequest();
    void startDataTransfer();

    typedef void (ServerStateData::*PreliminaryCb)();
    void forwardPreliminaryReply(const PreliminaryCb cb);
    void proceedAfterPreliminaryReply();
    PreliminaryCb thePreliminaryCb;

    enum {
        BEGIN,
        SENT_COMMAND,
        SENT_PASV,
        SENT_DATA_REQUEST,
        READING_DATA,
        DONE
    };
    typedef void (ServerStateData::*SM_FUNC)();
    static const SM_FUNC SM_FUNCS[];
    void readWelcome();
    void sendCommand();
    void readReply();
    void readPasvReply();
    void readDataReply();
    void readTransferDoneReply();

    virtual void dataChannelConnected(const Comm::ConnectionPointer &conn, comm_err_t err, int xerrno);
    void scheduleReadControlReply();

    CBDATA_CLASS2(ServerStateData);
};

CBDATA_CLASS_INIT(ServerStateData);

const ServerStateData::SM_FUNC ServerStateData::SM_FUNCS[] = {
    &ServerStateData::readWelcome, // BEGIN
    &ServerStateData::readReply, // SENT_COMMAND
    &ServerStateData::readPasvReply, // SENT_PASV
    &ServerStateData::readDataReply, // SENT_DATA_REQUEST
    &ServerStateData::readTransferDoneReply, // READING_DATA
    NULL // DONE
};

ServerStateData::ServerStateData(FwdState *const fwdState):
    AsyncJob("Ftp::Gateway::ServerStateData"), Ftp::ServerStateData(fwdState)
{
}

ServerStateData::~ServerStateData()
{
    if (Comm::IsConnOpen(ctrl.conn)) {
        fwd->unregister(ctrl.conn);
        ctrl.forget();
    }
}

void
ServerStateData::start()
{
    if (clientState() == ConnStateData::FTP_BEGIN)
        Ftp::ServerStateData::start();
    else
    if (clientState() == ConnStateData::FTP_HANDLE_DATA_REQUEST)
        handleDataRequest();
    else
        sendCommand();
}

ConnStateData::FtpState
ServerStateData::clientState() const
{
    return fwd->request->clientConnectionManager->ftp.state;
}

void
ServerStateData::clientState(ConnStateData::FtpState s) const
{
    fwd->request->clientConnectionManager->ftp.state = s;
}

void
ServerStateData::failed(err_type error, int xerrno)
{
    if (!doneWithServer())
        clientState(ConnStateData::FTP_ERROR);

    Ftp::ServerStateData::failed(error, xerrno);
}

void
ServerStateData::failedErrorMessage(err_type error, int xerrno)
{
    const Http::StatusCode httpStatus = failedHttpStatus(error);
    HttpReply *const reply = createHttpReply(httpStatus);
    entry->replaceHttpReply(reply);
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    fwd->request->detailError(error, xerrno);
}

void
ServerStateData::processReplyBody()
{
    debugs(9, 3, HERE << "starting");

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        /*
         * probably was aborted because content length exceeds one
         * of the maximum size limits.
         */
        abortTransaction("entry aborted after calling appendSuccessHeader()");
        return;
    }

#if USE_ADAPTATION

    if (adaptationAccessCheckPending) {
        debugs(9,3, HERE << "returning due to adaptationAccessCheckPending");
        return;
    }

#endif

    if (const int csize = data.readBuf->contentSize()) {
        debugs(9, 5, HERE << "writing " << csize << " bytes to the reply");
        addVirginReplyBody(data.readBuf->content(), csize);
        data.readBuf->consume(csize);
    }

    entry->flush();

    maybeReadVirginBody();
}

void
ServerStateData::handleControlReply()
{
    Ftp::ServerStateData::handleControlReply();
    if (ctrl.message == NULL)
        return; // didn't get complete reply yet

    assert(state < DONE);
    (this->*SM_FUNCS[state])();
}

void
ServerStateData::handleRequestBodyProducerAborted()
{
    ::ServerStateData::handleRequestBodyProducerAborted();

    abortTransaction("request body producer aborted");
}

bool
ServerStateData::doneWithServer() const
{
    return state == DONE || Ftp::ServerStateData::doneWithServer();
}

void
ServerStateData::forwardReply()
{
    assert(entry->isEmpty());
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);

    HttpReply *const reply = createHttpReply(Http::scOkay);

    setVirginReply(reply);
    adaptOrFinalizeReply();

    state = DONE;
    serverComplete();
}

void
ServerStateData::forwardPreliminaryReply(const PreliminaryCb cb)
{
    debugs(9, 5, HERE << "Forwarding preliminary reply to client");

    assert(thePreliminaryCb == NULL);
    thePreliminaryCb = cb;

    const HttpReply::Pointer reply = createHttpReply(Http::scContinue);

    // the Sink will use this to call us back after writing 1xx to the client
    typedef NullaryMemFunT<ServerStateData> CbDialer;
    const AsyncCall::Pointer call = JobCallback(11, 3, CbDialer, this,
        ServerStateData::proceedAfterPreliminaryReply);

    CallJobHere1(9, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::sendControlMsg, HttpControlMsg(reply, call));
}

void
ServerStateData::proceedAfterPreliminaryReply()
{
    debugs(9, 5, HERE << "Proceeding after preliminary reply to client");

    assert(thePreliminaryCb != NULL);
    const PreliminaryCb cb = thePreliminaryCb;
    thePreliminaryCb = NULL;
    (this->*cb)();
}

void
ServerStateData::forwardError(err_type error, int xerrno)
{
    state = DONE;
    failed(error, xerrno);
}

HttpReply *
ServerStateData::createHttpReply(const Http::StatusCode httpStatus, const int clen)
{
    HttpReply *const reply = new HttpReply;
    reply->sline.set(Http::ProtocolVersion(1, 1), httpStatus);
    HttpHeader &header = reply->header;
    header.putTime(HDR_DATE, squid_curtime);
    {
        HttpHdrCc cc;
        cc.Private();
        header.putCc(&cc);
    }
    if (clen >= 0)
        header.putInt64(HDR_CONTENT_LENGTH, clen);
    if (ctrl.replycode > 0)
        header.putInt(HDR_FTP_STATUS, ctrl.replycode);
    if (ctrl.message) {
        for (wordlist *W = ctrl.message; W; W = W->next)
            header.putStr(HDR_FTP_REASON, W->key);
    } else if (ctrl.last_command)
        header.putStr(HDR_FTP_REASON, ctrl.last_command);

    reply->hdrCacheInit();

    return reply;
}

void
ServerStateData::handleDataRequest()
{
    data.addr = fwd->request->clientConnectionManager->ftp.serverDataAddr;

    if (!data.addr.IsSockAddr()) { // should never happen
        debugs(9, DBG_IMPORTANT, HERE << "Inconsistent FTP server state: "
               "data.addr=" << data.addr);
        failed();
        return;
    }

    connectDataChannel();
}

void
ServerStateData::startDataTransfer()
{
    assert(Comm::IsConnOpen(data.conn));

    debugs(9, 3, HERE << "begin data transfer from " << data.conn->remote <<
           " (" << data.conn->local << ")");

    HttpReply *const reply = createHttpReply(Http::scOkay, -1);
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    setVirginReply(reply);
    adaptOrFinalizeReply();

    switchTimeoutToDataChannel();
    maybeReadVirginBody();
    state = READING_DATA;
}

void
ServerStateData::readWelcome()
{
    assert(clientState() == ConnStateData::FTP_BEGIN);

    switch (ctrl.replycode) {
    case 220:
        clientState(ConnStateData::FTP_CONNECTED);
        ctrl.replycode = 120; // change status for forwarded server greeting
        forwardPreliminaryReply(&ServerStateData::sendCommand);
        break;
    case 120:
        if (NULL != ctrl.message)
            debugs(9, DBG_IMPORTANT, "FTP server is busy: " << ctrl.message->key);
        forwardPreliminaryReply(&ServerStateData::scheduleReadControlReply);
        break;
    default:
        failed();
        break;
    }
}

void
ServerStateData::sendCommand()
{
    if (!fwd->request->header.has(HDR_FTP_COMMAND)) {
        abortTransaction("Internal error: FTP gateway request with no command");
        return;
    }

    String cmd = fwd->request->header.findEntry(HDR_FTP_COMMAND)->value;
    const String *const params = fwd->request->header.has(HDR_FTP_ARGUMENTS) ?
        &fwd->request->header.findEntry(HDR_FTP_ARGUMENTS)->value : NULL;

    if (params != NULL)
        debugs(9, 5, HERE << "command: " << cmd << ", parameters: " << *params);
    else
        debugs(9, 5, HERE << "command: " << cmd << ", no parameters");

    static MemBuf mb;
    mb.reset();
    if (params != NULL)
        mb.Printf("%s %s%s", cmd.termedBuf(), params->termedBuf(), Ftp::crlf);
    else
        mb.Printf("%s%s", cmd.termedBuf(), Ftp::crlf);

    writeCommand(mb.content());

    state = clientState() == ConnStateData::FTP_HANDLE_PASV ? SENT_PASV :
        clientState() == ConnStateData::FTP_HANDLE_DATA_REQUEST ? SENT_DATA_REQUEST :
        SENT_COMMAND;
}

void
ServerStateData::readReply()
{
    assert(clientState() == ConnStateData::FTP_CONNECTED);

    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        forwardPreliminaryReply(&ServerStateData::scheduleReadControlReply);
    else
        forwardReply();
}

void
ServerStateData::readPasvReply()
{
    assert(clientState() == ConnStateData::FTP_HANDLE_PASV);

    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        return; // ignore preliminary replies

    if (handlePasvReply()) {
        fwd->request->clientConnectionManager->ftp.serverDataAddr = data.addr;
        forwardReply();
    } else
        forwardError();
}

void
ServerStateData::readDataReply()
{
    assert(clientState() == ConnStateData::FTP_HANDLE_DATA_REQUEST);

    if (ctrl.replycode == 150)
        forwardPreliminaryReply(&ServerStateData::startDataTransfer);
    else
        forwardReply();
}

void
ServerStateData::readTransferDoneReply()
{
    debugs(9, 3, HERE);

    if (ctrl.replycode != 226 && ctrl.replycode != 250) {
        debugs(9, DBG_IMPORTANT, HERE << "Got code " << ctrl.replycode <<
               " after reading data");
    }

    state = DONE;
    serverComplete();
}

void
ServerStateData::dataChannelConnected(const Comm::ConnectionPointer &conn, comm_err_t err, int xerrno)
{
    debugs(9, 3, HERE);
    data.opener = NULL;

    if (err != COMM_OK) {
        debugs(9, 2, HERE << "Failed to connect FTP server data channel.");
        forwardError(ERR_CONNECT_FAIL, xerrno);
        return;
    }

    debugs(9, 2, HERE << "Connected FTP server data channel: " << conn);

    data.opened(conn, dataCloser());

    sendCommand();
}

void
ServerStateData::scheduleReadControlReply()
{
    Ftp::ServerStateData::scheduleReadControlReply(0);
}

}; // namespace Gateway

}; // namespace Ftp

void
ftpGatewayServerStart(FwdState *const fwdState)
{
    AsyncJob::Start(new Ftp::Gateway::ServerStateData(fwdState));
}
