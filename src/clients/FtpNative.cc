/*
 * DEBUG: section 09    File Transfer Protocol (FTP)
 *
 */

#include "squid.h"

#include "anyp/PortCfg.h"
#include "client_side.h"
#include "clients/FtpClient.h"
#include "ftp/Parsing.h"
#include "HttpHdrCc.h"
#include "HttpRequest.h"
#include "servers/FtpServer.h"
#include "Server.h"
#include "SquidTime.h"
#include "Store.h"
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

    const Ftp::MasterState &master() const;
    Ftp::MasterState &updateMaster();
    Ftp::ServerState clientState() const;
    void clientState(Ftp::ServerState newState);

    virtual void serverComplete();
    virtual void failed(err_type error = ERR_NONE, int xerrno = 0);
    virtual void handleControlReply();
    virtual void handleRequestBodyProducerAborted();
    virtual bool mayReadVirginReplyBody() const;
    virtual void completeForwarding();
    void forwardReply();
    void forwardError(err_type error = ERR_NONE, int xerrno = 0);
    void failedErrorMessage(err_type error, int xerrno);
    HttpReply *createHttpReply(const Http::StatusCode httpStatus, const int clen = 0);
    void handleDataRequest();
    void startDataDownload();
    void startDataUpload();
    bool startDirTracking();
    void stopDirTracking();
    bool weAreTrackingDir() const {return savedReply.message != NULL;}

    typedef void (ServerStateData::*PreliminaryCb)();
    void forwardPreliminaryReply(const PreliminaryCb cb);
    void proceedAfterPreliminaryReply();
    PreliminaryCb thePreliminaryCb;

    typedef void (ServerStateData::*SM_FUNC)();
    static const SM_FUNC SM_FUNCS[];
    void readGreeting();
    void sendCommand();
    void readReply();
    void readFeatReply();
    void readPasvReply();
    void readDataReply();
    void readTransferDoneReply();
    void readEpsvReply();
    void readCwdOrCdupReply();
    void readUserOrPassReply();

    virtual void dataChannelConnected(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno);
    void scheduleReadControlReply();

    bool forwardingCompleted; ///< completeForwarding() has been called

    struct {
        wordlist *message; ///< reply message, one  wordlist entry per message line
        char *lastCommand; ///< the command caused the reply
        char *lastReply; ///< last line of reply: reply status plus message
        int replyCode; ///< the reply status
    } savedReply; ///< set and delayed while we are tracking using PWD

    CBDATA_CLASS2(ServerStateData);
};

CBDATA_CLASS_INIT(ServerStateData);

const ServerStateData::SM_FUNC ServerStateData::SM_FUNCS[] = {
    &ServerStateData::readGreeting, // BEGIN
    &ServerStateData::readUserOrPassReply, // SENT_USER
    &ServerStateData::readUserOrPassReply, // SENT_PASS
    NULL,/*&ServerStateData::readReply*/ // SENT_TYPE
    NULL,/*&ServerStateData::readReply*/ // SENT_MDTM
    NULL,/*&ServerStateData::readReply*/ // SENT_SIZE
    NULL, // SENT_EPRT
    NULL, // SENT_PORT
    &ServerStateData::readEpsvReply, // SENT_EPSV_ALL
    &ServerStateData::readEpsvReply, // SENT_EPSV_1
    &ServerStateData::readEpsvReply, // SENT_EPSV_2
    &ServerStateData::readPasvReply, // SENT_PASV
    &ServerStateData::readCwdOrCdupReply,  // SENT_CWD
    NULL,/*&ServerStateData::readDataReply,*/ // SENT_LIST
    NULL,/*&ServerStateData::readDataReply,*/ // SENT_NLST
    NULL,/*&ServerStateData::readReply*/ // SENT_REST
    NULL,/*&ServerStateData::readDataReply*/ // SENT_RETR
    NULL,/*&ServerStateData::readReply*/ // SENT_STOR
    NULL,/*&ServerStateData::readReply*/ // SENT_QUIT
    &ServerStateData::readTransferDoneReply, // READING_DATA
    &ServerStateData::readReply, // WRITING_DATA
    NULL,/*&ServerStateData::readReply*/ // SENT_MKDIR
    &ServerStateData::readFeatReply, // SENT_FEAT
    NULL,/*&ServerStateData::readPwdReply*/ // SENT_PWD
    &ServerStateData::readCwdOrCdupReply, // SENT_CDUP
    &ServerStateData::readDataReply,// SENT_DATA_REQUEST
    &ServerStateData::readReply, // SENT_COMMAND
    NULL
};

ServerStateData::ServerStateData(FwdState *const fwdState):
    AsyncJob("Ftp::Gateway::ServerStateData"), Ftp::ServerStateData(fwdState),
    forwardingCompleted(false)
{
    savedReply.message = NULL;
    savedReply.lastCommand = NULL;
    savedReply.lastReply = NULL;
    savedReply.replyCode = 0;

    // Nothing we can do at request creation time can mark the response as
    // uncachable, unfortunately. This prevents "found KEY_PRIVATE" WARNINGs.
    entry->releaseRequest();
}

ServerStateData::~ServerStateData()
{
    closeServer(); // TODO: move to Server.cc?
    if (savedReply.message)
        wordlistDestroy(&savedReply.message);

    xfree(savedReply.lastCommand);
    xfree(savedReply.lastReply);
}

void
ServerStateData::start()
{
    if (!master().clientReadGreeting)
        Ftp::ServerStateData::start();
    else
    if (clientState() == fssHandleDataRequest ||
        clientState() == fssHandleUploadRequest)
        handleDataRequest();
    else
        sendCommand();
}

/// Keep control connection for future requests, after we are done with it.
/// Similar to COMPLETE_PERSISTENT_MSG handling in http.cc.
void
ServerStateData::serverComplete()
{
    CbcPointer<ConnStateData> &mgr = fwd->request->clientConnectionManager;
    if (mgr.valid()) {
        if (Comm::IsConnOpen(ctrl.conn)) {
            debugs(9, 7, "completing FTP server " << ctrl.conn <<
                   " after " << ctrl.replycode);
            fwd->unregister(ctrl.conn);
            if (ctrl.replycode == 221) { // Server sends FTP 221 before closing
                mgr->unpinConnection(false);
                ctrl.close();
            } else {
                mgr->pinConnection(ctrl.conn, fwd->request,
                                   ctrl.conn->getPeer(),
                                   fwd->request->flags.connectionAuth);
                ctrl.forget();
            }
        }
    }
    Ftp::ServerStateData::serverComplete();
}

Ftp::MasterState &
ServerStateData::updateMaster()
{
    CbcPointer<ConnStateData> &mgr = fwd->request->clientConnectionManager;
    if (mgr.valid()) {
        if (Ftp::Server *srv = dynamic_cast<Ftp::Server*>(mgr.get()))
            return srv->master;
    }
    // this code will not be necessary once the master is inside MasterXaction
    debugs(9, 3, "our server side is gone: " << mgr);
    static Ftp::MasterState Master;
    Master = Ftp::MasterState();
    return Master;
}

const Ftp::MasterState &
ServerStateData::master() const
{
    return const_cast<Ftp::Gateway::ServerStateData*>(this)->updateMaster();
}

Ftp::ServerState
ServerStateData::clientState() const
{
    return master().serverState;
}

void
ServerStateData::clientState(Ftp::ServerState newState)
{
    // XXX: s/client/server/g
    Ftp::ServerState &cltState = updateMaster().serverState;
    debugs(9, 3, "client state was " << cltState << " now: " << newState);
    cltState = newState;
}

/**
 * Ensure we do not double-complete on the forward entry.
 * We complete forwarding when the response adaptation is over 
 * (but we may still be waiting for 226 from the FTP server) and
 * also when we get that 226 from the server (and adaptation is done).
 *
 \todo Rewrite FwdState to ignore double completion?
 */
void
ServerStateData::completeForwarding()
{
    debugs(9, 5, forwardingCompleted);
    if (forwardingCompleted)
        return;
    forwardingCompleted = true;
    Ftp::ServerStateData::completeForwarding();
}

void
ServerStateData::failed(err_type error, int xerrno)
{
    if (!doneWithServer())
        clientState(fssError);

    // TODO: we need to customize ErrorState instead
    if (entry->isEmpty())
        failedErrorMessage(error, xerrno); // as a reply

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

    if (data.readBuf != NULL && data.readBuf->hasContent()) {
        const mb_size_t csize = data.readBuf->contentSize();
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
    if (!request->clientConnectionManager.valid()) {
        debugs(9, 5, "client connection gone");
        closeServer();
        return;
    }

    Ftp::ServerStateData::handleControlReply();
    if (ctrl.message == NULL)
        return; // didn't get complete reply yet

    assert(state < END);
    assert(this->SM_FUNCS[state] != NULL);
    (this->*SM_FUNCS[state])();
}

void
ServerStateData::handleRequestBodyProducerAborted()
{
    ::ServerStateData::handleRequestBodyProducerAborted();

    failed(ERR_READ_ERROR);
}

bool
ServerStateData::mayReadVirginReplyBody() const
{
    // TODO: move this method to the regular FTP server?
    return Comm::IsConnOpen(data.conn);
}

void
ServerStateData::forwardReply()
{
    assert(entry->isEmpty());
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);

    HttpReply *const reply = createHttpReply(Http::scNoContent);

    setVirginReply(reply);
    adaptOrFinalizeReply();

    serverComplete();
}

void
ServerStateData::forwardPreliminaryReply(const PreliminaryCb cb)
{
    debugs(9, 5, HERE << "Forwarding preliminary reply to client");

    // we must prevent concurrent ConnStateData::sendControlMsg() calls
    Must(thePreliminaryCb == NULL);
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

    Must(thePreliminaryCb != NULL);
    const PreliminaryCb cb = thePreliminaryCb;
    thePreliminaryCb = NULL;
    (this->*cb)();
}

void
ServerStateData::forwardError(err_type error, int xerrno)
{
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

    if (ctrl.message) {
        for (wordlist *W = ctrl.message; W && W->next; W = W->next)
            header.putStr(HDR_FTP_PRE, httpHeaderQuoteString(W->key).termedBuf());
    }
    if (ctrl.replycode > 0)
        header.putInt(HDR_FTP_STATUS, ctrl.replycode);
    if (ctrl.last_reply)
        header.putStr(HDR_FTP_REASON, ctrl.last_reply);

    reply->hdrCacheInit();

    return reply;
}

void
ServerStateData::handleDataRequest()
{
    data.addr(master().clientDataAddr);
    connectDataChannel();
}

void
ServerStateData::startDataDownload()
{
    assert(Comm::IsConnOpen(data.conn));

    debugs(9, 3, HERE << "begin data transfer from " << data.conn->remote <<
           " (" << data.conn->local << ")");

    HttpReply *const reply = createHttpReply(Http::scOkay, -1);
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    setVirginReply(reply);
    adaptOrFinalizeReply();

    maybeReadVirginBody();
    state = READING_DATA;
}

void
ServerStateData::startDataUpload()
{
    assert(Comm::IsConnOpen(data.conn));

    debugs(9, 3, HERE << "begin data transfer to " << data.conn->remote <<
           " (" << data.conn->local << ")");

    if (!startRequestBodyFlow()) { // register to receive body data
        failed();
        return;
    }

    state = WRITING_DATA;
}

void
ServerStateData::readGreeting()
{
    assert(!master().clientReadGreeting);

    switch (ctrl.replycode) {
    case 220:
        updateMaster().clientReadGreeting = true;
        if (clientState() == fssBegin)
            clientState(fssConnected);

        // Do not forward server greeting to the client because our client
        // side code has greeted the client already. Also, a greeting may
        // confuse a client that has changed the gateway destination mid-air.

        start();
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

    HttpHeader &header = fwd->request->header;
    assert(header.has(HDR_FTP_COMMAND));
    const String &cmd = header.findEntry(HDR_FTP_COMMAND)->value;
    assert(header.has(HDR_FTP_ARGUMENTS));
    const String &params = header.findEntry(HDR_FTP_ARGUMENTS)->value;

    if (params.size() > 0)
        debugs(9, 5, HERE << "command: " << cmd << ", parameters: " << params);
    else
        debugs(9, 5, HERE << "command: " << cmd << ", no parameters");

    if (clientState() == fssHandlePasv ||
        clientState() == fssHandleEpsv ||
        clientState() == fssHandleEprt ||
        clientState() == fssHandlePort) {
        sendPassive();
        return;
    }

    static MemBuf mb;
    mb.reset();
    if (params.size() > 0)
        mb.Printf("%s %s%s", cmd.termedBuf(), params.termedBuf(), Ftp::crlf);
    else
        mb.Printf("%s%s", cmd.termedBuf(), Ftp::crlf);

    writeCommand(mb.content());

    state =
        clientState() == fssHandleCdup ? SENT_CDUP :
        clientState() == fssHandleCwd ? SENT_CWD :
        clientState() == fssHandleFeat ? SENT_FEAT :
        clientState() == fssHandleDataRequest ? SENT_DATA_REQUEST :
        clientState() == fssHandleUploadRequest ? SENT_DATA_REQUEST :
        clientState() == fssConnected ? SENT_USER :
        clientState() == fssHandlePass ? SENT_PASS :
        SENT_COMMAND;
}

void
ServerStateData::readReply()
{
    assert(clientState() == fssConnected ||
           clientState() == fssHandleUploadRequest);

    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        forwardPreliminaryReply(&ServerStateData::scheduleReadControlReply);
    else
        forwardReply();
}

void
ServerStateData::readFeatReply()
{
    assert(clientState() == fssHandleFeat);

    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        return; // ignore preliminary replies

    forwardReply();
}

void
ServerStateData::readPasvReply()
{
    assert(clientState() == fssHandlePasv || clientState() == fssHandleEpsv || clientState() == fssHandlePort || clientState() == fssHandleEprt);

    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        return; // ignore preliminary replies

    if (handlePasvReply(updateMaster().clientDataAddr))
        forwardReply();
    else
        forwardError();
}

void
ServerStateData::readEpsvReply()
{
    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        return; // ignore preliminary replies

    if (handleEpsvReply(updateMaster().clientDataAddr)) {
        if (ctrl.message == NULL)
            return; // didn't get complete reply yet

        forwardReply();
    } else
        forwardError();
}

void
ServerStateData::readDataReply()
{
    assert(clientState() == fssHandleDataRequest ||
           clientState() == fssHandleUploadRequest);

    if (ctrl.replycode == 125 || ctrl.replycode == 150) {
        if (clientState() == fssHandleDataRequest)
            forwardPreliminaryReply(&ServerStateData::startDataDownload);
        else // clientState() == fssHandleUploadRequest
            forwardPreliminaryReply(&ServerStateData::startDataUpload);
    } else
        forwardReply();
}

bool
ServerStateData::startDirTracking()
{
    if (!fwd->request->clientConnectionManager->port->ftp_track_dirs)
        return false;

    debugs(9, 5, "Start directory tracking");
    savedReply.message = ctrl.message;
    savedReply.lastCommand = ctrl.last_command;
    savedReply.lastReply = ctrl.last_reply;
    savedReply.replyCode = ctrl.replycode;

    ctrl.last_command = NULL;
    ctrl.last_reply = NULL;
    ctrl.message = NULL;
    ctrl.offset = 0;
    writeCommand("PWD\r\n");
    return true;
}

void
ServerStateData::stopDirTracking()
{
    debugs(9, 5, "Got code from pwd: " << ctrl.replycode << ", msg: " << ctrl.last_reply);

    if (ctrl.replycode == 257)
        updateMaster().workingDir = Ftp::UnescapeDoubleQuoted(ctrl.last_reply);

    wordlistDestroy(&ctrl.message);
    safe_free(ctrl.last_command);
    safe_free(ctrl.last_reply);

    ctrl.message = savedReply.message;
    ctrl.last_command = savedReply.lastCommand;
    ctrl.last_reply = savedReply.lastReply;
    ctrl.replycode = savedReply.replyCode;

    savedReply.message = NULL;
    savedReply.lastReply = NULL;
    savedReply.lastCommand = NULL;
}

void
ServerStateData::readCwdOrCdupReply()
{
    assert(clientState() == fssHandleCwd ||
           clientState() == fssHandleCdup);

    debugs(9, 5, HERE << "Got code " << ctrl.replycode << ", msg: " << ctrl.last_reply);

    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        return;

    if (weAreTrackingDir()) { // we are tracking
        stopDirTracking(); // and forward the delayed response below
    } else if (startDirTracking())
        return;

    forwardReply();
}

void
ServerStateData::readUserOrPassReply()
{
    if (100 <= ctrl.replycode && ctrl.replycode < 200)
        return; //Just ignore

    if (weAreTrackingDir()) { // we are tracking
        stopDirTracking(); // and forward the delayed response below
    } else if (ctrl.replycode == 230) { // successful login
        if (startDirTracking())
            return;
    }

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

    serverComplete();
}

void
ServerStateData::dataChannelConnected(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno)
{
    debugs(9, 3, HERE);
    data.opener = NULL;

    if (err != Comm::OK) {
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
