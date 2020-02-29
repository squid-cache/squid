/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 09    File Transfer Protocol (FTP) */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "client_side.h"
#include "clients/forward.h"
#include "clients/FtpClient.h"
#include "ftp/Elements.h"
#include "ftp/Parsing.h"
#include "http/Stream.h"
#include "HttpHdrCc.h"
#include "HttpRequest.h"
#include "sbuf/SBuf.h"
#include "servers/FtpServer.h"
#include "SquidTime.h"
#include "Store.h"
#include "wordlist.h"

namespace Ftp
{

/// An FTP client receiving native FTP commands from our FTP server
/// (Ftp::Server), forwarding them to the next FTP hop,
/// and then relaying FTP replies back to our FTP server.
class Relay: public Ftp::Client
{
    CBDATA_CLASS(Relay);

public:
    explicit Relay(FwdState *const fwdState);
    virtual ~Relay();

protected:
    const Ftp::MasterState &master() const;
    Ftp::MasterState &updateMaster();
    Ftp::ServerState serverState() const { return master().serverState; }
    void serverState(const Ftp::ServerState newState);

    /* Ftp::Client API */
    virtual void failed(err_type error = ERR_NONE, int xerrno = 0, ErrorState *ftperr = nullptr);
    virtual void dataChannelConnected(const CommConnectCbParams &io);

    /* Client API */
    virtual void serverComplete();
    virtual void handleControlReply();
    virtual void processReplyBody();
    virtual void handleRequestBodyProducerAborted();
    virtual bool mayReadVirginReplyBody() const;
    virtual void completeForwarding();
    virtual bool abortOnData(const char *reason);

    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();

    void forwardReply();
    void forwardError(err_type error = ERR_NONE, int xerrno = 0);
    void failedErrorMessage(err_type error, int xerrno);
    HttpReply *createHttpReply(const Http::StatusCode httpStatus, const int64_t clen = 0);
    void handleDataRequest();
    void startDataDownload();
    void startDataUpload();
    bool startDirTracking();
    void stopDirTracking();
    bool weAreTrackingDir() const {return savedReply.message != NULL;}

    typedef void (Relay::*PreliminaryCb)();
    void forwardPreliminaryReply(const PreliminaryCb cb);
    void proceedAfterPreliminaryReply();
    PreliminaryCb thePreliminaryCb;

    typedef void (Relay::*SM_FUNC)();
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

    void scheduleReadControlReply();

    /// Inform Ftp::Server that we are done if originWaitInProgress
    void stopOriginWait(int code);

    static void abort(void *d); // TODO: Capitalize this and FwdState::abort().

    bool forwardingCompleted; ///< completeForwarding() has been called

    /// whether we are between Ftp::Server::startWaitingForOrigin() and
    /// Ftp::Server::stopWaitingForOrigin() calls
    bool originWaitInProgress;

    struct {
        wordlist *message; ///< reply message, one  wordlist entry per message line
        char *lastCommand; ///< the command caused the reply
        char *lastReply; ///< last line of reply: reply status plus message
        int replyCode; ///< the reply status
    } savedReply; ///< set and delayed while we are tracking using PWD
};

} // namespace Ftp

CBDATA_NAMESPACED_CLASS_INIT(Ftp, Relay);

const Ftp::Relay::SM_FUNC Ftp::Relay::SM_FUNCS[] = {
    &Ftp::Relay::readGreeting, // BEGIN
    &Ftp::Relay::readUserOrPassReply, // SENT_USER
    &Ftp::Relay::readUserOrPassReply, // SENT_PASS
    NULL,/* &Ftp::Relay::readReply */ // SENT_TYPE
    NULL,/* &Ftp::Relay::readReply */ // SENT_MDTM
    NULL,/* &Ftp::Relay::readReply */ // SENT_SIZE
    NULL, // SENT_EPRT
    NULL, // SENT_PORT
    &Ftp::Relay::readEpsvReply, // SENT_EPSV_ALL
    &Ftp::Relay::readEpsvReply, // SENT_EPSV_1
    &Ftp::Relay::readEpsvReply, // SENT_EPSV_2
    &Ftp::Relay::readPasvReply, // SENT_PASV
    &Ftp::Relay::readCwdOrCdupReply,  // SENT_CWD
    NULL,/* &Ftp::Relay::readDataReply, */ // SENT_LIST
    NULL,/* &Ftp::Relay::readDataReply, */ // SENT_NLST
    NULL,/* &Ftp::Relay::readReply */ // SENT_REST
    NULL,/* &Ftp::Relay::readDataReply */ // SENT_RETR
    NULL,/* &Ftp::Relay::readReply */ // SENT_STOR
    NULL,/* &Ftp::Relay::readReply */ // SENT_QUIT
    &Ftp::Relay::readTransferDoneReply, // READING_DATA
    &Ftp::Relay::readReply, // WRITING_DATA
    NULL,/* &Ftp::Relay::readReply */ // SENT_MKDIR
    &Ftp::Relay::readFeatReply, // SENT_FEAT
    NULL,/* &Ftp::Relay::readPwdReply */ // SENT_PWD
    &Ftp::Relay::readCwdOrCdupReply, // SENT_CDUP
    &Ftp::Relay::readDataReply,// SENT_DATA_REQUEST
    &Ftp::Relay::readReply, // SENT_COMMAND
    NULL
};

Ftp::Relay::Relay(FwdState *const fwdState):
    AsyncJob("Ftp::Relay"),
    Ftp::Client(fwdState),
    thePreliminaryCb(NULL),
    forwardingCompleted(false),
    originWaitInProgress(false)
{
    savedReply.message = NULL;
    savedReply.lastCommand = NULL;
    savedReply.lastReply = NULL;
    savedReply.replyCode = 0;

    // Nothing we can do at request creation time can mark the response as
    // uncachable, unfortunately. This prevents "found KEY_PRIVATE" WARNINGs.
    entry->releaseRequest();
    // TODO: Convert registerAbort() to use AsyncCall
    entry->registerAbort(Ftp::Relay::abort, this);
}

Ftp::Relay::~Relay()
{
    closeServer(); // TODO: move to clients/Client.cc?
    if (savedReply.message)
        wordlistDestroy(&savedReply.message);

    xfree(savedReply.lastCommand);
    xfree(savedReply.lastReply);
}

void
Ftp::Relay::start()
{
    if (!master().clientReadGreeting)
        Ftp::Client::start();
    else if (serverState() == fssHandleDataRequest ||
             serverState() == fssHandleUploadRequest)
        handleDataRequest();
    else
        sendCommand();
}

void
Ftp::Relay::swanSong()
{
    stopOriginWait(0);
    Ftp::Client::swanSong();
}

/// Keep control connection for future requests, after we are done with it.
/// Similar to COMPLETE_PERSISTENT_MSG handling in http.cc.
void
Ftp::Relay::serverComplete()
{
    stopOriginWait(ctrl.replycode);

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
                CallJobHere1(9, 4, mgr,
                             ConnStateData,
                             notePinnedConnectionBecameIdle,
                             ConnStateData::PinnedIdleContext(ctrl.conn, fwd->request));
                ctrl.forget();
            }
        }
    }
    Ftp::Client::serverComplete();
}

/// Safely returns the master state,
/// with safety checks in case the Ftp::Server side of the master xact is gone.
Ftp::MasterState &
Ftp::Relay::updateMaster()
{
    CbcPointer<ConnStateData> &mgr = fwd->request->clientConnectionManager;
    if (mgr.valid()) {
        if (Ftp::Server *srv = dynamic_cast<Ftp::Server*>(mgr.get()))
            return *srv->master;
    }
    // this code will not be necessary once the master is inside MasterXaction
    debugs(9, 3, "our server side is gone: " << mgr);
    static Ftp::MasterState Master;
    Master = Ftp::MasterState();
    return Master;
}

/// A const variant of updateMaster().
const Ftp::MasterState &
Ftp::Relay::master() const
{
    return const_cast<Ftp::Relay*>(this)->updateMaster(); // avoid code dupe
}

/// Changes server state and debugs about that important event.
void
Ftp::Relay::serverState(const Ftp::ServerState newState)
{
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
Ftp::Relay::completeForwarding()
{
    debugs(9, 5, forwardingCompleted);
    if (forwardingCompleted)
        return;
    forwardingCompleted = true;
    Ftp::Client::completeForwarding();
}

void
Ftp::Relay::failed(err_type error, int xerrno, ErrorState *ftpErr)
{
    if (!doneWithServer())
        serverState(fssError);

    // TODO: we need to customize ErrorState instead
    if (entry->isEmpty())
        failedErrorMessage(error, xerrno); // as a reply

    Ftp::Client::failed(error, xerrno, ftpErr);
}

void
Ftp::Relay::failedErrorMessage(err_type error, int xerrno)
{
    const Http::StatusCode httpStatus = failedHttpStatus(error);
    HttpReply *const reply = createHttpReply(httpStatus);
    entry->replaceHttpReply(reply);
    fwd->request->detailError(error, xerrno);
}

void
Ftp::Relay::processReplyBody()
{
    debugs(9, 3, status());

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        /*
         * probably was aborted because content length exceeds one
         * of the maximum size limits.
         */
        abortOnData("entry aborted after calling appendSuccessHeader()");
        return;
    }

    if (master().userDataDone) {
        // Squid-to-client data transfer done. Abort data transfer on our
        // side to allow new commands from ftp client
        abortOnData("Squid-to-client data connection is closed");
        return;
    }

#if USE_ADAPTATION

    if (adaptationAccessCheckPending) {
        debugs(9, 3, "returning due to adaptationAccessCheckPending");
        return;
    }

#endif

    if (data.readBuf != NULL && data.readBuf->hasContent()) {
        const mb_size_t csize = data.readBuf->contentSize();
        debugs(9, 5, "writing " << csize << " bytes to the reply");
        addVirginReplyBody(data.readBuf->content(), csize);
        data.readBuf->consume(csize);
    }

    entry->flush();

    maybeReadVirginBody();
}

void
Ftp::Relay::handleControlReply()
{
    if (!request->clientConnectionManager.valid()) {
        debugs(9, 5, "client connection gone");
        closeServer();
        return;
    }

    Ftp::Client::handleControlReply();
    if (ctrl.message == NULL)
        return; // didn't get complete reply yet

    assert(state < END);
    assert(this->SM_FUNCS[state] != NULL);
    (this->*SM_FUNCS[state])();
}

void
Ftp::Relay::handleRequestBodyProducerAborted()
{
    ::Client::handleRequestBodyProducerAborted();

    failed(ERR_READ_ERROR);
}

bool
Ftp::Relay::mayReadVirginReplyBody() const
{
    // TODO: move this method to the regular FTP server?
    return Comm::IsConnOpen(data.conn);
}

void
Ftp::Relay::forwardReply()
{
    assert(entry->isEmpty());

    HttpReply *const reply = createHttpReply(Http::scNoContent);
    reply->sources |= Http::Message::srcFtp;

    setVirginReply(reply);
    adaptOrFinalizeReply();

    serverComplete();
}

void
Ftp::Relay::forwardPreliminaryReply(const PreliminaryCb cb)
{
    debugs(9, 5, "forwarding preliminary reply to client");

    // we must prevent concurrent ConnStateData::sendControlMsg() calls
    Must(thePreliminaryCb == NULL);
    thePreliminaryCb = cb;

    const HttpReply::Pointer reply = createHttpReply(Http::scContinue);

    // the Sink will use this to call us back after writing 1xx to the client
    typedef NullaryMemFunT<Relay> CbDialer;
    const AsyncCall::Pointer call = JobCallback(11, 3, CbDialer, this,
                                    Ftp::Relay::proceedAfterPreliminaryReply);

    CallJobHere1(9, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::sendControlMsg, HttpControlMsg(reply, call));
}

void
Ftp::Relay::proceedAfterPreliminaryReply()
{
    debugs(9, 5, "proceeding after preliminary reply to client");

    Must(thePreliminaryCb != NULL);
    const PreliminaryCb cb = thePreliminaryCb;
    thePreliminaryCb = NULL;
    (this->*cb)();
}

void
Ftp::Relay::forwardError(err_type error, int xerrno)
{
    failed(error, xerrno);
}

HttpReply *
Ftp::Relay::createHttpReply(const Http::StatusCode httpStatus, const int64_t clen)
{
    HttpReply *const reply = Ftp::HttpReplyWrapper(ctrl.replycode, ctrl.last_reply, httpStatus, clen);
    if (ctrl.message) {
        for (wordlist *W = ctrl.message; W && W->next; W = W->next)
            reply->header.putStr(Http::HdrType::FTP_PRE, httpHeaderQuoteString(W->key).c_str());
        // no hdrCacheInit() is needed for after Http::HdrType::FTP_PRE addition
    }
    return reply;
}

void
Ftp::Relay::handleDataRequest()
{
    data.addr(master().clientDataAddr);
    connectDataChannel();
}

void
Ftp::Relay::startDataDownload()
{
    assert(Comm::IsConnOpen(data.conn));

    debugs(9, 3, "begin data transfer from " << data.conn->remote <<
           " (" << data.conn->local << ")");

    HttpReply *const reply = createHttpReply(Http::scOkay, -1);
    reply->sources |= Http::Message::srcFtp;

    setVirginReply(reply);
    adaptOrFinalizeReply();

    maybeReadVirginBody();
    state = READING_DATA;
}

void
Ftp::Relay::startDataUpload()
{
    assert(Comm::IsConnOpen(data.conn));

    debugs(9, 3, "begin data transfer to " << data.conn->remote <<
           " (" << data.conn->local << ")");

    if (!startRequestBodyFlow()) { // register to receive body data
        failed();
        return;
    }

    state = WRITING_DATA;
}

void
Ftp::Relay::readGreeting()
{
    assert(!master().clientReadGreeting);

    switch (ctrl.replycode) {
    case 220:
        updateMaster().clientReadGreeting = true;
        if (serverState() == fssBegin)
            serverState(fssConnected);

        // Do not forward server greeting to the user because our FTP Server
        // has greeted the user already. Also, an original origin greeting may
        // confuse a user that has changed the origin mid-air.

        start();
        break;
    case 120:
        if (NULL != ctrl.message)
            debugs(9, DBG_IMPORTANT, "FTP server is busy: " << ctrl.message->key);
        forwardPreliminaryReply(&Ftp::Relay::scheduleReadControlReply);
        break;
    default:
        failed();
        break;
    }
}

void
Ftp::Relay::sendCommand()
{
    if (!fwd->request->header.has(Http::HdrType::FTP_COMMAND)) {
        abortAll("Internal error: FTP relay request with no command");
        return;
    }

    HttpHeader &header = fwd->request->header;
    assert(header.has(Http::HdrType::FTP_COMMAND));
    const String &cmd = header.findEntry(Http::HdrType::FTP_COMMAND)->value;
    assert(header.has(Http::HdrType::FTP_ARGUMENTS));
    const String &params = header.findEntry(Http::HdrType::FTP_ARGUMENTS)->value;

    if (params.size() > 0)
        debugs(9, 5, "command: " << cmd << ", parameters: " << params);
    else
        debugs(9, 5, "command: " << cmd << ", no parameters");

    if (serverState() == fssHandlePasv ||
            serverState() == fssHandleEpsv ||
            serverState() == fssHandleEprt ||
            serverState() == fssHandlePort) {
        sendPassive();
        return;
    }

    SBuf buf;
    if (params.size() > 0)
        buf.Printf("%s %s%s", cmd.termedBuf(), params.termedBuf(), Ftp::crlf);
    else
        buf.Printf("%s%s", cmd.termedBuf(), Ftp::crlf);

    writeCommand(buf.c_str());

    state =
        serverState() == fssHandleCdup ? SENT_CDUP :
        serverState() == fssHandleCwd ? SENT_CWD :
        serverState() == fssHandleFeat ? SENT_FEAT :
        serverState() == fssHandleDataRequest ? SENT_DATA_REQUEST :
        serverState() == fssHandleUploadRequest ? SENT_DATA_REQUEST :
        serverState() == fssConnected ? SENT_USER :
        serverState() == fssHandlePass ? SENT_PASS :
        SENT_COMMAND;

    if (state == SENT_DATA_REQUEST) {
        CbcPointer<ConnStateData> &mgr = fwd->request->clientConnectionManager;
        if (mgr.valid()) {
            if (Ftp::Server *srv = dynamic_cast<Ftp::Server*>(mgr.get())) {
                typedef NullaryMemFunT<Ftp::Server> CbDialer;
                AsyncCall::Pointer call = JobCallback(11, 3, CbDialer, srv,
                                                      Ftp::Server::startWaitingForOrigin);
                ScheduleCallHere(call);
                originWaitInProgress = true;
            }
        }
    }
}

void
Ftp::Relay::readReply()
{
    assert(serverState() == fssConnected ||
           serverState() == fssHandleUploadRequest);

    if (Is1xx(ctrl.replycode))
        forwardPreliminaryReply(&Ftp::Relay::scheduleReadControlReply);
    else
        forwardReply();
}

void
Ftp::Relay::readFeatReply()
{
    assert(serverState() == fssHandleFeat);

    if (Is1xx(ctrl.replycode))
        return; // ignore preliminary replies

    forwardReply();
}

void
Ftp::Relay::readPasvReply()
{
    assert(serverState() == fssHandlePasv || serverState() == fssHandleEpsv || serverState() == fssHandlePort || serverState() == fssHandleEprt);

    if (Is1xx(ctrl.replycode))
        return; // ignore preliminary replies

    if (handlePasvReply(updateMaster().clientDataAddr))
        forwardReply();
    else
        forwardError();
}

void
Ftp::Relay::readEpsvReply()
{
    if (Is1xx(ctrl.replycode))
        return; // ignore preliminary replies

    if (handleEpsvReply(updateMaster().clientDataAddr)) {
        if (ctrl.message == NULL)
            return; // didn't get complete reply yet

        forwardReply();
    } else
        forwardError();
}

void
Ftp::Relay::readDataReply()
{
    assert(serverState() == fssHandleDataRequest ||
           serverState() == fssHandleUploadRequest);

    if (ctrl.replycode == 125 || ctrl.replycode == 150) {
        if (serverState() == fssHandleDataRequest)
            forwardPreliminaryReply(&Ftp::Relay::startDataDownload);
        else if (fwd->request->forcedBodyContinuation /*&& serverState() == fssHandleUploadRequest*/)
            startDataUpload();
        else // serverState() == fssHandleUploadRequest
            forwardPreliminaryReply(&Ftp::Relay::startDataUpload);
    } else
        forwardReply();
}

bool
Ftp::Relay::startDirTracking()
{
    if (!fwd->request->clientConnectionManager->port->ftp_track_dirs)
        return false;

    debugs(9, 5, "start directory tracking");
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
Ftp::Relay::stopDirTracking()
{
    debugs(9, 5, "got code from pwd: " << ctrl.replycode << ", msg: " << ctrl.last_reply);

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
Ftp::Relay::readCwdOrCdupReply()
{
    assert(serverState() == fssHandleCwd ||
           serverState() == fssHandleCdup);

    debugs(9, 5, "got code " << ctrl.replycode << ", msg: " << ctrl.last_reply);

    if (Is1xx(ctrl.replycode))
        return;

    if (weAreTrackingDir()) { // we are tracking
        stopDirTracking(); // and forward the delayed response below
    } else if (startDirTracking())
        return;

    forwardReply();
}

void
Ftp::Relay::readUserOrPassReply()
{
    if (Is1xx(ctrl.replycode))
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
Ftp::Relay::readTransferDoneReply()
{
    debugs(9, 3, status());

    if (ctrl.replycode != 226 && ctrl.replycode != 250) {
        debugs(9, DBG_IMPORTANT, "got FTP code " << ctrl.replycode <<
               " after reading response data");
    }

    debugs(9, 2, "Complete data downloading");

    serverComplete();
}

void
Ftp::Relay::dataChannelConnected(const CommConnectCbParams &io)
{
    debugs(9, 3, status());
    data.opener = NULL;

    if (io.flag != Comm::OK) {
        debugs(9, 2, "failed to connect FTP server data channel");
        forwardError(ERR_CONNECT_FAIL, io.xerrno);
        return;
    }

    debugs(9, 2, "connected FTP server data channel: " << io.conn);

    data.opened(io.conn, dataCloser());

    sendCommand();
}

void
Ftp::Relay::scheduleReadControlReply()
{
    Ftp::Client::scheduleReadControlReply(0);
}

bool
Ftp::Relay::abortOnData(const char *reason)
{
    debugs(9, 3, "aborting transaction for " << reason <<
           "; FD " << (ctrl.conn != NULL ? ctrl.conn->fd : -1) << ", Data FD " << (data.conn != NULL ? data.conn->fd : -1) << ", this " << this);
    // this method is only called to handle data connection problems
    // the control connection should keep going

#if USE_ADAPTATION
    if (adaptedBodySource != NULL)
        stopConsumingFrom(adaptedBodySource);
#endif

    if (Comm::IsConnOpen(data.conn))
        dataComplete();

    return !Comm::IsConnOpen(ctrl.conn);
}

void
Ftp::Relay::stopOriginWait(int code)
{
    if (originWaitInProgress) {
        CbcPointer<ConnStateData> &mgr = fwd->request->clientConnectionManager;
        if (mgr.valid()) {
            if (Ftp::Server *srv = dynamic_cast<Ftp::Server*>(mgr.get())) {
                typedef UnaryMemFunT<Ftp::Server, int> CbDialer;
                AsyncCall::Pointer call = asyncCall(11, 3, "Ftp::Server::stopWaitingForOrigin",
                                                    CbDialer(srv, &Ftp::Server::stopWaitingForOrigin, code));
                ScheduleCallHere(call);
            }
        }
        originWaitInProgress = false;
    }
}

void
Ftp::Relay::abort(void *d)
{
    Ftp::Relay *ftpClient = (Ftp::Relay *)d;
    debugs(9, 2, "Client Data connection closed!");
    if (!cbdataReferenceValid(ftpClient))
        return;
    if (Comm::IsConnOpen(ftpClient->data.conn))
        ftpClient->dataComplete();
}

AsyncJob::Pointer
Ftp::StartRelay(FwdState *const fwdState)
{
    return AsyncJob::Start(new Ftp::Relay(fwdState));
}

