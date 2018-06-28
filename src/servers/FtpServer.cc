/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Transfer protocol servers */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/CharacterSet.h"
#include "base/RefCount.h"
#include "base/Subscription.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "clientStream.h"
#include "comm/ConnOpener.h"
#include "comm/Read.h"
#include "comm/TcpAcceptor.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "ftp/Elements.h"
#include "ftp/Parsing.h"
#include "globals.h"
#include "http/one/RequestParser.h"
#include "http/Stream.h"
#include "HttpHdrCc.h"
#include "ip/tools.h"
#include "ipc/FdNotes.h"
#include "parser/Tokenizer.h"
#include "servers/forward.h"
#include "servers/FtpServer.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "tools.h"

#include <set>
#include <map>

CBDATA_NAMESPACED_CLASS_INIT(Ftp, Server);

namespace Ftp
{
static void PrintReply(MemBuf &mb, const HttpReply *reply, const char *const prefix = "");
static bool SupportedCommand(const SBuf &name);
static bool CommandHasPathParameter(const SBuf &cmd);
};

Ftp::Server::Server(const MasterXaction::Pointer &xact):
    AsyncJob("Ftp::Server"),
    ConnStateData(xact),
    master(new MasterState),
    uri(),
    host(),
    gotEpsvAll(false),
    onDataAcceptCall(),
    dataListenConn(),
    dataConn(),
    uploadAvailSize(0),
    listener(),
    connector(),
    reader(),
    waitingForOrigin(false),
    originDataDownloadAbortedOnError(false)
{
    flags.readMore = false; // we need to announce ourselves first
    *uploadBuf = 0;
}

Ftp::Server::~Server()
{
    closeDataConnection();
}

int
Ftp::Server::pipelinePrefetchMax() const
{
    return 0; // no support for concurrent FTP requests
}

time_t
Ftp::Server::idleTimeout() const
{
    return Config.Timeout.ftpClientIdle;
}

void
Ftp::Server::start()
{
    ConnStateData::start();

    if (transparent()) {
        char buf[MAX_IPSTRLEN];
        clientConnection->local.toUrl(buf, MAX_IPSTRLEN);
        host = buf;
        calcUri(NULL);
        debugs(33, 5, "FTP transparent URL: " << uri);
    }

    writeEarlyReply(220, "Service ready");
}

/// schedules another data connection read if needed
void
Ftp::Server::maybeReadUploadData()
{
    if (reader != NULL)
        return;

    const size_t availSpace = sizeof(uploadBuf) - uploadAvailSize;
    if (availSpace <= 0)
        return;

    debugs(33, 4, dataConn << ": reading FTP data...");

    typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
    reader = JobCallback(33, 5, Dialer, this, Ftp::Server::readUploadData);
    comm_read(dataConn, uploadBuf + uploadAvailSize, availSpace,
              reader);
}

/// react to the freshly parsed request
void
Ftp::Server::doProcessRequest()
{
    // zero pipelinePrefetchMax() ensures that there is only parsed request
    Must(pipeline.count() == 1);
    Http::StreamPointer context = pipeline.front();
    Must(context != nullptr);

    ClientHttpRequest *const http = context->http;
    assert(http != NULL);

    HttpRequest *const request = http->request;
    Must(http->storeEntry() || request);
    const bool mayForward = !http->storeEntry() && handleRequest(request);

    if (http->storeEntry() != NULL) {
        debugs(33, 4, "got an immediate response");
        clientSetKeepaliveFlag(http);
        context->pullData();
    } else if (mayForward) {
        debugs(33, 4, "forwarding request to server side");
        assert(http->storeEntry() == NULL);
        clientProcessRequest(this, Http1::RequestParserPointer(), context.getRaw());
    } else {
        debugs(33, 4, "will resume processing later");
    }
}

void
Ftp::Server::processParsedRequest(Http::StreamPointer &)
{
    Must(pipeline.count() == 1);

    // Process FTP request asynchronously to make sure FTP
    // data connection accept callback is fired first.
    CallJobHere(33, 4, CbcPointer<Server>(this),
                Ftp::Server, doProcessRequest);
}

/// imports more upload data from the data connection
void
Ftp::Server::readUploadData(const CommIoCbParams &io)
{
    debugs(33, 5, io.conn << " size " << io.size);
    Must(reader != NULL);
    reader = NULL;

    assert(Comm::IsConnOpen(dataConn));
    assert(io.conn->fd == dataConn->fd);

    if (io.flag == Comm::OK && bodyPipe != NULL) {
        if (io.size > 0) {
            statCounter.client_http.kbytes_in += io.size;

            char *const current_buf = uploadBuf + uploadAvailSize;
            if (io.buf != current_buf)
                memmove(current_buf, io.buf, io.size);
            uploadAvailSize += io.size;
            shovelUploadData();
        } else if (io.size == 0) {
            debugs(33, 5, io.conn << " closed");
            closeDataConnection();
            if (uploadAvailSize <= 0)
                finishDechunkingRequest(true);
        }
    } else { // not Comm::Flags::OK or unexpected read
        debugs(33, 5, io.conn << " closed");
        closeDataConnection();
        finishDechunkingRequest(false);
    }

}

/// shovel upload data from the internal buffer to the body pipe if possible
void
Ftp::Server::shovelUploadData()
{
    assert(bodyPipe != NULL);

    debugs(33, 5, "handling FTP request data for " << clientConnection);
    const size_t putSize = bodyPipe->putMoreData(uploadBuf,
                           uploadAvailSize);
    if (putSize > 0) {
        uploadAvailSize -= putSize;
        if (uploadAvailSize > 0)
            memmove(uploadBuf, uploadBuf + putSize, uploadAvailSize);
    }

    if (Comm::IsConnOpen(dataConn))
        maybeReadUploadData();
    else if (uploadAvailSize <= 0)
        finishDechunkingRequest(true);
}

void
Ftp::Server::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    if (!isOpen()) // if we are closing, nothing to do
        return;

    shovelUploadData();
}

void
Ftp::Server::noteBodyConsumerAborted(BodyPipe::Pointer ptr)
{
    if (!isOpen()) // if we are closing, nothing to do
        return;

    ConnStateData::noteBodyConsumerAborted(ptr);
    closeDataConnection();
}

/// accept a new FTP control connection and hand it to a dedicated Server
void
Ftp::Server::AcceptCtrlConnection(const CommAcceptCbParams &params)
{
    MasterXaction::Pointer xact = params.xaction;
    AnyP::PortCfgPointer s = xact->squidPort;

    // NP: it is possible the port was reconfigured when the call or accept() was queued.

    if (params.flag != Comm::OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, s->listenConn << ": FTP accept failure: " << xstrerr(params.xerrno));
        return;
    }

    debugs(33, 4, params.conn << ": accepted");
    fd_note(params.conn->fd, "client ftp connect");

    if (s->tcp_keepalive.enabled)
        commSetTcpKeepalive(params.conn->fd, s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);

    ++incoming_sockets_accepted;

    AsyncJob::Start(new Server(xact));
}

void
Ftp::StartListening()
{
    for (AnyP::PortCfgPointer s = FtpPortList; s != NULL; s = s->next) {
        if (MAXTCPLISTENPORTS == NHttpSockets) {
            debugs(1, DBG_IMPORTANT, "Ignoring ftp_port lines exceeding the" <<
                   " limit of " << MAXTCPLISTENPORTS << " ports.");
            break;
        }

        // direct new connections accepted by listenConn to Accept()
        typedef CommCbFunPtrCallT<CommAcceptCbPtrFun> AcceptCall;
        RefCount<AcceptCall> subCall = commCbCall(5, 5, "Ftp::Server::AcceptCtrlConnection",
                                       CommAcceptCbPtrFun(Ftp::Server::AcceptCtrlConnection,
                                               CommAcceptCbParams(NULL)));
        clientStartListeningOn(s, subCall, Ipc::fdnFtpSocket);
    }
}

void
Ftp::StopListening()
{
    for (AnyP::PortCfgPointer s = FtpPortList; s != NULL; s = s->next) {
        if (s->listenConn != NULL) {
            debugs(1, DBG_IMPORTANT, "Closing FTP port " << s->listenConn->local);
            s->listenConn->close();
            s->listenConn = NULL;
        }
    }
}

void
Ftp::Server::notePeerConnection(Comm::ConnectionPointer conn)
{
    // find request
    Http::StreamPointer context = pipeline.front();
    Must(context != nullptr);
    ClientHttpRequest *const http = context->http;
    Must(http != NULL);
    HttpRequest *const request = http->request;
    Must(request != NULL);
    // make FTP peer connection exclusive to our request
    pinBusyConnection(conn, request);
}

void
Ftp::Server::clientPinnedConnectionClosed(const CommCloseCbParams &io)
{
    ConnStateData::clientPinnedConnectionClosed(io);

    // TODO: Keep the control connection open after fixing the reset
    // problem below
    if (Comm::IsConnOpen(clientConnection))
        clientConnection->close();

    // TODO: If the server control connection is gone, reset state to login
    // again. Reseting login alone is not enough: FtpRelay::sendCommand() will
    // not re-login because FtpRelay::serverState() is not going to be
    // fssConnected. Calling resetLogin() alone is also harmful because
    // it does not reset correctly the client-to-squid control connection (eg
    // respond if required with an error code, in all cases)
    // resetLogin("control connection closure");
}

/// clear client and server login-related state after the old login is gone
void
Ftp::Server::resetLogin(const char *reason)
{
    debugs(33, 5, "will need to re-login due to " << reason);
    master->clientReadGreeting = false;
    changeState(fssBegin, reason);
}

/// computes uri member from host and, if tracked, working dir with file name
void
Ftp::Server::calcUri(const SBuf *file)
{
    // TODO: fill a class AnyP::Uri instead of string
    uri = "ftp://";
    uri.append(host);
    if (port->ftp_track_dirs && master->workingDir.length()) {
        if (master->workingDir[0] != '/')
            uri.append("/", 1);
        uri.append(master->workingDir);
    }

    if (uri[uri.length() - 1] != '/')
        uri.append("/", 1);

    if (port->ftp_track_dirs && file) {
        static const CharacterSet Slash("/", "/");
        Parser::Tokenizer tok(*file);
        tok.skipAll(Slash);
        uri.append(tok.remaining());
    }
}

/// Starts waiting for a data connection. Returns listening port.
/// On errors, responds with an error and returns zero.
unsigned int
Ftp::Server::listenForDataConnection()
{
    closeDataConnection();

    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->flags = COMM_NONBLOCKING;
    conn->local = transparent() ? port->s : clientConnection->local;
    conn->local.port(0);
    const char *const note = uri.c_str();
    comm_open_listener(SOCK_STREAM, IPPROTO_TCP, conn, note);
    if (!Comm::IsConnOpen(conn)) {
        debugs(5, DBG_CRITICAL, "comm_open_listener failed for FTP data: " <<
               conn->local << " error: " << errno);
        writeCustomReply(451, "Internal error");
        return 0;
    }

    typedef CommCbMemFunT<Server, CommAcceptCbParams> AcceptDialer;
    typedef AsyncCallT<AcceptDialer> AcceptCall;
    RefCount<AcceptCall> call = static_cast<AcceptCall*>(JobCallback(5, 5, AcceptDialer, this, Ftp::Server::acceptDataConnection));
    Subscription::Pointer sub = new CallSubscription<AcceptCall>(call);
    listener = call.getRaw();
    dataListenConn = conn;
    AsyncJob::Start(new Comm::TcpAcceptor(conn, note, sub));

    const unsigned int listeningPort = comm_local_port(conn->fd);
    conn->local.port(listeningPort);
    return listeningPort;
}

void
Ftp::Server::acceptDataConnection(const CommAcceptCbParams &params)
{
    if (params.flag != Comm::OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, dataListenConn << ": accept "
               "failure: " << xstrerr(params.xerrno));
        return;
    }

    debugs(33, 4, "accepted " << params.conn);
    fd_note(params.conn->fd, "passive client ftp data");
    ++incoming_sockets_accepted;

    if (!clientConnection) {
        debugs(33, 5, "late data connection?");
        closeDataConnection(); // in case we are still listening
        params.conn->close();
    } else if (params.conn->remote != clientConnection->remote) {
        debugs(33, 2, "rogue data conn? ctrl: " << clientConnection->remote);
        params.conn->close();
        // Some FTP servers close control connection here, but it may make
        // things worse from DoS p.o.v. and no better from data stealing p.o.v.
    } else {
        closeDataConnection();
        dataConn = params.conn;
        uploadAvailSize = 0;
        debugs(33, 7, "ready for data");
        if (onDataAcceptCall != NULL) {
            AsyncCall::Pointer call = onDataAcceptCall;
            onDataAcceptCall = NULL;
            // If we got an upload request, start reading data from the client.
            if (master->serverState == fssHandleUploadRequest)
                maybeReadUploadData();
            else
                Must(master->serverState == fssHandleDataRequest);
            MemBuf mb;
            mb.init();
            mb.appendf("150 Data connection opened.\r\n");
            Comm::Write(clientConnection, &mb, call);
        }
    }
}

void
Ftp::Server::closeDataConnection()
{
    if (listener != NULL) {
        listener->cancel("no longer needed");
        listener = NULL;
    }

    if (Comm::IsConnOpen(dataListenConn)) {
        debugs(33, 5, "FTP closing client data listen socket: " <<
               *dataListenConn);
        dataListenConn->close();
    }
    dataListenConn = NULL;

    if (reader != NULL) {
        // Comm::ReadCancel can deal with negative FDs
        Comm::ReadCancel(dataConn->fd, reader);
        reader = NULL;
    }

    if (Comm::IsConnOpen(dataConn)) {
        debugs(33, 5, "FTP closing client data connection: " <<
               *dataConn);
        dataConn->close();
    }
    dataConn = NULL;
}

/// Writes FTP [error] response before we fully parsed the FTP request and
/// created the corresponding HTTP request wrapper for that FTP request.
void
Ftp::Server::writeEarlyReply(const int code, const char *msg)
{
    debugs(33, 7, code << ' ' << msg);
    assert(99 < code && code < 1000);

    MemBuf mb;
    mb.init();
    mb.appendf("%i %s\r\n", code, msg);

    typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, Ftp::Server::wroteEarlyReply);
    Comm::Write(clientConnection, &mb, call);

    flags.readMore = false;

    // TODO: Create master transaction. Log it in wroteEarlyReply().
}

void
Ftp::Server::writeReply(MemBuf &mb)
{
    debugs(9, 2, "FTP Client " << clientConnection);
    debugs(9, 2, "FTP Client REPLY:\n---------\n" << mb.buf <<
           "\n----------");

    typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, Ftp::Server::wroteReply);
    Comm::Write(clientConnection, &mb, call);
}

void
Ftp::Server::writeCustomReply(const int code, const char *msg, const HttpReply *reply)
{
    debugs(33, 7, code << ' ' << msg);
    assert(99 < code && code < 1000);

    const bool sendDetails = reply != NULL &&
                             reply->header.has(Http::HdrType::FTP_STATUS) && reply->header.has(Http::HdrType::FTP_REASON);

    MemBuf mb;
    mb.init();
    if (sendDetails) {
        mb.appendf("%i-%s\r\n", code, msg);
        mb.appendf(" Server reply:\r\n");
        Ftp::PrintReply(mb, reply, " ");
        mb.appendf("%i \r\n", code);
    } else
        mb.appendf("%i %s\r\n", code, msg);

    writeReply(mb);
}

void
Ftp::Server::changeState(const ServerState newState, const char *reason)
{
    if (master->serverState == newState) {
        debugs(33, 3, "client state unchanged at " << master->serverState <<
               " because " << reason);
        master->serverState = newState;
    } else {
        debugs(33, 3, "client state was " << master->serverState <<
               ", now " << newState << " because " << reason);
        master->serverState = newState;
    }
}

/// whether the given FTP command has a pathname parameter
static bool
Ftp::CommandHasPathParameter(const SBuf &cmd)
{
    static std::set<SBuf> PathedCommands;
    if (!PathedCommands.size()) {
        PathedCommands.insert(cmdMlst());
        PathedCommands.insert(cmdMlsd());
        PathedCommands.insert(cmdStat());
        PathedCommands.insert(cmdNlst());
        PathedCommands.insert(cmdList());
        PathedCommands.insert(cmdMkd());
        PathedCommands.insert(cmdRmd());
        PathedCommands.insert(cmdDele());
        PathedCommands.insert(cmdRnto());
        PathedCommands.insert(cmdRnfr());
        PathedCommands.insert(cmdAppe());
        PathedCommands.insert(cmdStor());
        PathedCommands.insert(cmdRetr());
        PathedCommands.insert(cmdSmnt());
        PathedCommands.insert(cmdCwd());
    }

    return PathedCommands.find(cmd) != PathedCommands.end();
}

/// creates a context filled with an error message for a given early error
Http::Stream *
Ftp::Server::earlyError(const EarlyErrorKind eek)
{
    /* Default values, to be updated by the switch statement below */
    int scode = 421;
    const char *reason = "Internal error";
    const char *errUri = "error:ftp-internal-early-error";

    switch (eek) {
    case EarlyErrorKind::HugeRequest:
        scode = 421;
        reason = "Huge request";
        errUri = "error:ftp-huge-request";
        break;

    case EarlyErrorKind::MissingLogin:
        scode = 530;
        reason = "Must login first";
        errUri = "error:ftp-must-login-first";
        break;

    case EarlyErrorKind::MissingUsername:
        scode = 501;
        reason = "Missing username";
        errUri = "error:ftp-missing-username";
        break;

    case EarlyErrorKind::MissingHost:
        scode = 501;
        reason = "Missing host";
        errUri = "error:ftp-missing-host";
        break;

    case EarlyErrorKind::UnsupportedCommand:
        scode = 502;
        reason = "Unknown or unsupported command";
        errUri = "error:ftp-unsupported-command";
        break;

    case EarlyErrorKind::InvalidUri:
        scode = 501;
        reason = "Invalid URI";
        errUri = "error:ftp-invalid-uri";
        break;

    case EarlyErrorKind::MalformedCommand:
        scode = 421;
        reason = "Malformed command";
        errUri = "error:ftp-malformed-command";
        break;

        // no default so that a compiler can check that we have covered all cases
    }

    Http::Stream *context = abortRequestParsing(errUri);
    clientStreamNode *node = context->getClientReplyContext();
    Must(node);
    clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
    Must(repContext);

    // We cannot relay FTP scode/reason via HTTP-specific ErrorState.
    // TODO: When/if ErrorState can handle native FTP errors, use it instead.
    HttpReply *reply = Ftp::HttpReplyWrapper(scode, reason, Http::scBadRequest, -1);
    repContext->setReplyToReply(reply);
    return context;
}

/// Parses a single FTP request on the control connection.
/// Returns a new Http::Stream on valid requests and all errors.
/// Returns NULL on incomplete requests that may still succeed given more data.
Http::Stream *
Ftp::Server::parseOneRequest()
{
    flags.readMore = false; // common for all but one case below

    // OWS <command> [ RWS <parameter> ] OWS LF

    // InlineSpaceChars are isspace(3) or RFC 959 Section 3.1.1.5.2, except
    // for the LF character that we must exclude here (but see FullWhiteSpace).
    static const char * const InlineSpaceChars = " \f\r\t\v";
    static const CharacterSet InlineSpace = CharacterSet("Ftp::Inline", InlineSpaceChars);
    static const CharacterSet FullWhiteSpace = (InlineSpace + CharacterSet::LF).rename("Ftp::FWS");
    static const CharacterSet CommandChars = FullWhiteSpace.complement("Ftp::Command");
    static const CharacterSet TailChars = CharacterSet::LF.complement("Ftp::Tail");

    // This set is used to ignore empty commands without allowing an attacker
    // to keep us endlessly busy by feeding us whitespace or empty commands.
    static const CharacterSet &LeadingSpace = FullWhiteSpace;

    SBuf cmd;
    SBuf params;

    Parser::Tokenizer tok(inBuf);

    (void)tok.skipAll(LeadingSpace); // leading OWS and empty commands
    const bool parsed = tok.prefix(cmd, CommandChars); // required command

    // note that the condition below will eat either RWS or trailing OWS
    if (parsed && tok.skipAll(InlineSpace) && tok.prefix(params, TailChars)) {
        // now params may include trailing OWS
        // TODO: Support right-trimming using CharacterSet in Tokenizer instead
        static const SBuf bufWhiteSpace(InlineSpaceChars);
        params.trim(bufWhiteSpace, false, true);
    }

    // Why limit command line and parameters size? Did not we just parse them?
    // XXX: Our good old String cannot handle very long strings.
    const SBuf::size_type tokenMax = min(
                                         static_cast<SBuf::size_type>(32*1024), // conservative
                                         static_cast<SBuf::size_type>(Config.maxRequestHeaderSize));
    if (cmd.length() > tokenMax || params.length() > tokenMax) {
        changeState(fssError, "huge req token");
        quitAfterError(NULL);
        return earlyError(EarlyErrorKind::HugeRequest);
    }

    // technically, we may skip multiple NLs below, but that is OK
    if (!parsed || !tok.skipAll(CharacterSet::LF)) { // did not find terminating LF yet
        // we need more data, but can we buffer more?
        if (inBuf.length() >= Config.maxRequestHeaderSize) {
            changeState(fssError, "huge req");
            quitAfterError(NULL);
            return earlyError(EarlyErrorKind::HugeRequest);
        } else {
            flags.readMore = true;
            debugs(33, 5, "Waiting for more, up to " <<
                   (Config.maxRequestHeaderSize - inBuf.length()));
            return NULL;
        }
    }

    Must(parsed && cmd.length());
    consumeInput(tok.parsedSize()); // TODO: Would delaying optimize copying?

    debugs(33, 2, ">>ftp " << cmd << (params.isEmpty() ? "" : " ") << params);

    cmd.toUpper(); // this should speed up and simplify future comparisons

    // interception cases do not need USER to calculate the uri
    if (!transparent()) {
        if (!master->clientReadGreeting) {
            // the first command must be USER
            if (!pinning.pinned && cmd != cmdUser())
                return earlyError(EarlyErrorKind::MissingLogin);
        }

        // process USER request now because it sets FTP peer host name
        if (cmd == cmdUser()) {
            if (Http::Stream *errCtx = handleUserRequest(cmd, params))
                return errCtx;
        }
    }

    if (!Ftp::SupportedCommand(cmd))
        return earlyError(EarlyErrorKind::UnsupportedCommand);

    const HttpRequestMethod method =
        cmd == cmdAppe() || cmd == cmdStor() || cmd == cmdStou() ?
        Http::METHOD_PUT : Http::METHOD_GET;

    const SBuf *path = (params.length() && CommandHasPathParameter(cmd)) ?
                       &params : NULL;
    calcUri(path);
    MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initClient);
    mx->tcpClient = clientConnection;
    HttpRequest *const request = HttpRequest::FromUrl(uri.c_str(), mx, method);
    if (!request) {
        debugs(33, 5, "Invalid FTP URL: " << uri);
        uri.clear();
        return earlyError(EarlyErrorKind::InvalidUri);
    }
    char *newUri = xstrdup(uri.c_str());

    request->flags.ftpNative = true;
    request->http_ver = Http::ProtocolVersion(Ftp::ProtocolVersion().major, Ftp::ProtocolVersion().minor);

    // Our fake Request-URIs are not distinctive enough for caching to work
    request->flags.cachable = false; // XXX: reset later by maybeCacheable()
    request->flags.noCache = true;

    request->header.putStr(Http::HdrType::FTP_COMMAND, cmd.c_str());
    request->header.putStr(Http::HdrType::FTP_ARGUMENTS, params.c_str()); // may be ""
    if (method == Http::METHOD_PUT) {
        request->header.putStr(Http::HdrType::EXPECT, "100-continue");
        request->header.putStr(Http::HdrType::TRANSFER_ENCODING, "chunked");
    }

    ClientHttpRequest *const http = new ClientHttpRequest(this);
    http->request = request;
    HTTPMSGLOCK(http->request);
    http->req_sz = tok.parsedSize();
    http->uri = newUri;

    Http::Stream *const result =
        new Http::Stream(clientConnection, http);

    StoreIOBuffer tempBuffer;
    tempBuffer.data = result->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;

    ClientStreamData newServer = new clientReplyContext(http);
    ClientStreamData newClient = result;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, newServer, clientSocketRecipient,
                     clientSocketDetach, newClient, tempBuffer);

    result->flags.parsed_ok = 1;
    return result;
}

void
Ftp::Server::handleReply(HttpReply *reply, StoreIOBuffer data)
{
    // the caller guarantees that we are dealing with the current context only
    Http::StreamPointer context = pipeline.front();
    assert(context != nullptr);

    if (context->http && context->http->al != NULL &&
            !context->http->al->reply && reply) {
        context->http->al->reply = reply;
        HTTPMSGLOCK(context->http->al->reply);
    }

    static ReplyHandler handlers[] = {
        NULL, // fssBegin
        NULL, // fssConnected
        &Ftp::Server::handleFeatReply, // fssHandleFeat
        &Ftp::Server::handlePasvReply, // fssHandlePasv
        &Ftp::Server::handlePortReply, // fssHandlePort
        &Ftp::Server::handleDataReply, // fssHandleDataRequest
        &Ftp::Server::handleUploadReply, // fssHandleUploadRequest
        &Ftp::Server::handleEprtReply,// fssHandleEprt
        &Ftp::Server::handleEpsvReply,// fssHandleEpsv
        NULL, // fssHandleCwd
        NULL, // fssHandlePass
        NULL, // fssHandleCdup
        &Ftp::Server::handleErrorReply // fssError
    };
    try {
        const Server &server = dynamic_cast<const Ftp::Server&>(*context->getConn());
        if (const ReplyHandler handler = handlers[server.master->serverState])
            (this->*handler)(reply, data);
        else
            writeForwardedReply(reply);
    } catch (const std::exception &e) {
        callException(e);
        throw TexcHere(e.what());
    }
}

void
Ftp::Server::handleFeatReply(const HttpReply *reply, StoreIOBuffer)
{
    if (pipeline.front()->http->request->errType != ERR_NONE) {
        writeCustomReply(502, "Server does not support FEAT", reply);
        return;
    }

    Must(reply);
    HttpReply::Pointer featReply = Ftp::HttpReplyWrapper(211, "End", Http::scNoContent, 0);
    HttpHeader const &serverReplyHeader = reply->header;

    HttpHeaderPos pos = HttpHeaderInitPos;
    bool hasEPRT = false;
    bool hasEPSV = false;
    int prependSpaces = 1;

    featReply->header.putStr(Http::HdrType::FTP_PRE, "\"211-Features:\"");
    const int scode = serverReplyHeader.getInt(Http::HdrType::FTP_STATUS);
    if (scode == 211) {
        while (const HttpHeaderEntry *e = serverReplyHeader.getEntry(&pos)) {
            if (e->id == Http::HdrType::FTP_PRE) {
                // assume RFC 2389 FEAT response format, quoted by Squid:
                // <"> SP NAME [SP PARAMS] <">
                // but accommodate MS servers sending four SPs before NAME

                // command name ends with (SP parameter) or quote
                static const CharacterSet AfterFeatNameChars("AfterFeatName", " \"");
                static const CharacterSet FeatNameChars = AfterFeatNameChars.complement("FeatName");

                Parser::Tokenizer tok(SBuf(e->value.termedBuf()));
                if (!tok.skip('"') || !tok.skip(' '))
                    continue;

                // optional spaces; remember their number to accomodate MS servers
                prependSpaces = 1 + tok.skipAll(CharacterSet::SP);

                SBuf cmd;
                if (!tok.prefix(cmd, FeatNameChars))
                    continue;
                cmd.toUpper();

                if (Ftp::SupportedCommand(cmd)) {
                    featReply->header.addEntry(e->clone());
                }

                if (cmd == cmdEprt())
                    hasEPRT = true;
                else if (cmd == cmdEpsv())
                    hasEPSV = true;
            }
        }
    } // else we got a FEAT error and will only report Squid-supported features

    char buf[256];
    if (!hasEPRT) {
        snprintf(buf, sizeof(buf), "\"%*s\"", prependSpaces + 4, "EPRT");
        featReply->header.putStr(Http::HdrType::FTP_PRE, buf);
    }
    if (!hasEPSV) {
        snprintf(buf, sizeof(buf), "\"%*s\"", prependSpaces + 4, "EPSV");
        featReply->header.putStr(Http::HdrType::FTP_PRE, buf);
    }

    featReply->header.refreshMask();

    writeForwardedReply(featReply.getRaw());
}

void
Ftp::Server::handlePasvReply(const HttpReply *reply, StoreIOBuffer)
{
    const Http::StreamPointer context(pipeline.front());
    assert(context != nullptr);

    if (context->http->request->errType != ERR_NONE) {
        writeCustomReply(502, "Server does not support PASV", reply);
        return;
    }

    const unsigned short localPort = listenForDataConnection();
    if (!localPort)
        return;

    char addr[MAX_IPSTRLEN];
    // remote server in interception setups and local address otherwise
    const Ip::Address &server = transparent() ?
                                clientConnection->local : dataListenConn->local;
    server.toStr(addr, MAX_IPSTRLEN, AF_INET);
    addr[MAX_IPSTRLEN - 1] = '\0';
    for (char *c = addr; *c != '\0'; ++c) {
        if (*c == '.')
            *c = ',';
    }

    // In interception setups, we combine remote server address with a
    // local port number and hope that traffic will be redirected to us.
    // Do not use "227 =a,b,c,d,p1,p2" format or omit parens: some nf_ct_ftp
    // versions block responses that use those alternative syntax rules!
    MemBuf mb;
    mb.init();
    mb.appendf("227 Entering Passive Mode (%s,%i,%i).\r\n",
               addr,
               static_cast<int>(localPort / 256),
               static_cast<int>(localPort % 256));
    debugs(9, 3, Raw("writing", mb.buf, mb.size));
    writeReply(mb);
}

void
Ftp::Server::handlePortReply(const HttpReply *reply, StoreIOBuffer)
{
    if (pipeline.front()->http->request->errType != ERR_NONE) {
        writeCustomReply(502, "Server does not support PASV (converted from PORT)", reply);
        return;
    }

    writeCustomReply(200, "PORT successfully converted to PASV.");

    // and wait for RETR
}

void
Ftp::Server::handleErrorReply(const HttpReply *reply, StoreIOBuffer)
{
    if (!pinning.pinned) // we failed to connect to server
        uri.clear();
    // 421: we will close due to fssError
    writeErrorReply(reply, 421);
}

void
Ftp::Server::handleDataReply(const HttpReply *reply, StoreIOBuffer data)
{
    if (reply != NULL && reply->sline.status() != Http::scOkay) {
        writeForwardedReply(reply);
        if (Comm::IsConnOpen(dataConn)) {
            debugs(33, 3, "closing " << dataConn << " on KO reply");
            closeDataConnection();
        }
        return;
    }

    if (!dataConn) {
        // We got STREAM_COMPLETE (or error) and closed the client data conn.
        debugs(33, 3, "ignoring FTP srv data response after clt data closure");
        return;
    }

    if (!checkDataConnPost()) {
        writeCustomReply(425, "Data connection is not established.");
        closeDataConnection();
        return;
    }

    debugs(33, 7, data.length);

    if (data.length <= 0) {
        replyDataWritingCheckpoint(); // skip the actual write call
        return;
    }

    MemBuf mb;
    mb.init(data.length + 1, data.length + 1);
    mb.append(data.data, data.length);

    typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, Ftp::Server::wroteReplyData);
    Comm::Write(dataConn, &mb, call);

    pipeline.front()->noteSentBodyBytes(data.length);
}

/// called when we are done writing a chunk of the response data
void
Ftp::Server::wroteReplyData(const CommIoCbParams &io)
{
    if (io.flag == Comm::ERR_CLOSING)
        return;

    if (io.flag != Comm::OK) {
        debugs(33, 3, "FTP reply data writing failed: " << xstrerr(io.xerrno));
        userDataCompletionCheckpoint(426);
        return;
    }

    assert(pipeline.front()->http);
    pipeline.front()->http->out.size += io.size;
    replyDataWritingCheckpoint();
}

/// ClientStream checks after (actual or skipped) reply data writing
void
Ftp::Server::replyDataWritingCheckpoint()
{
    switch (pipeline.front()->socketState()) {
    case STREAM_NONE:
        debugs(33, 3, "Keep going");
        pipeline.front()->pullData();
        return;
    case STREAM_COMPLETE:
        debugs(33, 3, "FTP reply data transfer successfully complete");
        userDataCompletionCheckpoint(226);
        break;
    case STREAM_UNPLANNED_COMPLETE:
        debugs(33, 3, "FTP reply data transfer failed: STREAM_UNPLANNED_COMPLETE");
        userDataCompletionCheckpoint(451);
        break;
    case STREAM_FAILED:
        userDataCompletionCheckpoint(451);
        debugs(33, 3, "FTP reply data transfer failed: STREAM_FAILED");
        break;
    default:
        fatal("unreachable code");
    }
}

void
Ftp::Server::handleUploadReply(const HttpReply *reply, StoreIOBuffer)
{
    writeForwardedReply(reply);
    // note that the client data connection may already be closed by now
}

void
Ftp::Server::writeForwardedReply(const HttpReply *reply)
{
    Must(reply);

    if (waitingForOrigin) {
        Must(delayedReply == NULL);
        delayedReply = reply;
        return;
    }

    const HttpHeader &header = reply->header;
    // adaptation and forwarding errors lack Http::HdrType::FTP_STATUS
    if (!header.has(Http::HdrType::FTP_STATUS)) {
        writeForwardedForeign(reply); // will get to Ftp::Server::wroteReply
        return;
    }

    typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, Ftp::Server::wroteReply);
    writeForwardedReplyAndCall(reply, call);
}

void
Ftp::Server::handleEprtReply(const HttpReply *reply, StoreIOBuffer)
{
    if (pipeline.front()->http->request->errType != ERR_NONE) {
        writeCustomReply(502, "Server does not support PASV (converted from EPRT)", reply);
        return;
    }

    writeCustomReply(200, "EPRT successfully converted to PASV.");

    // and wait for RETR
}

void
Ftp::Server::handleEpsvReply(const HttpReply *reply, StoreIOBuffer)
{
    if (pipeline.front()->http->request->errType != ERR_NONE) {
        writeCustomReply(502, "Cannot connect to server", reply);
        return;
    }

    const unsigned short localPort = listenForDataConnection();
    if (!localPort)
        return;

    // In interception setups, we use a local port number and hope that data
    // traffic will be redirected to us.
    MemBuf mb;
    mb.init();
    mb.appendf("229 Entering Extended Passive Mode (|||%u|)\r\n", localPort);

    debugs(9, 3, Raw("writing", mb.buf, mb.size));
    writeReply(mb);
}

/// writes FTP error response with given status and reply-derived error details
void
Ftp::Server::writeErrorReply(const HttpReply *reply, const int scode)
{
    const HttpRequest *request = pipeline.front()->http->request;
    assert(request);

    MemBuf mb;
    mb.init();

    if (request->errType != ERR_NONE)
        mb.appendf("%i-%s\r\n", scode, errorPageName(request->errType));

    if (request->errDetail > 0) {
        // XXX: > 0 may not always mean that this is an errno
        mb.appendf("%i-Error: (%d) %s\r\n", scode,
                   request->errDetail,
                   strerror(request->errDetail));
    }

#if USE_ADAPTATION
    // XXX: Remove hard coded names. Use an error page template instead.
    const Adaptation::History::Pointer ah = request->adaptHistory();
    if (ah != NULL) { // XXX: add adapt::<all_h but use lastMeta here
        const String info = ah->allMeta.getByName("X-Response-Info");
        const String desc = ah->allMeta.getByName("X-Response-Desc");
        if (info.size())
            mb.appendf("%i-Information: %s\r\n", scode, info.termedBuf());
        if (desc.size())
            mb.appendf("%i-Description: %s\r\n", scode, desc.termedBuf());
    }
#endif

    const char *reason = "Lost Error";
    if (reply) {
        reason = reply->header.has(Http::HdrType::FTP_REASON) ?
                 reply->header.getStr(Http::HdrType::FTP_REASON):
                 reply->sline.reason();
    }

    mb.appendf("%i %s\r\n", scode, reason); // error terminating line

    // TODO: errorpage.cc should detect FTP client and use
    // configurable FTP-friendly error templates which we should
    // write to the client "as is" instead of hiding most of the info

    writeReply(mb);
}

/// writes FTP response based on HTTP reply that is not an FTP-response wrapper
/// for example, internally-generated Squid "errorpages" end up here (for now)
void
Ftp::Server::writeForwardedForeign(const HttpReply *reply)
{
    changeState(fssConnected, "foreign reply");
    closeDataConnection();
    // 451: We intend to keep the control connection open.
    writeErrorReply(reply, 451);
}

bool
Ftp::Server::writeControlMsgAndCall(HttpReply *reply, AsyncCall::Pointer &call)
{
    // the caller guarantees that we are dealing with the current context only
    // the caller should also make sure reply->header.has(Http::HdrType::FTP_STATUS)
    writeForwardedReplyAndCall(reply, call);
    return true;
}

void
Ftp::Server::writeForwardedReplyAndCall(const HttpReply *reply, AsyncCall::Pointer &call)
{
    assert(reply != NULL);
    const HttpHeader &header = reply->header;

    // without status, the caller must use the writeForwardedForeign() path
    Must(header.has(Http::HdrType::FTP_STATUS));
    Must(header.has(Http::HdrType::FTP_REASON));
    const int scode = header.getInt(Http::HdrType::FTP_STATUS);
    debugs(33, 7, "scode: " << scode);

    // Status 125 or 150 implies upload or data request, but we still check
    // the state in case the server is buggy.
    if ((scode == 125 || scode == 150) &&
            (master->serverState == fssHandleUploadRequest ||
             master->serverState == fssHandleDataRequest)) {
        if (checkDataConnPost()) {
            // If the data connection is ready, start reading data (here)
            // and forward the response to client (further below).
            debugs(33, 7, "data connection established, start data transfer");
            if (master->serverState == fssHandleUploadRequest)
                maybeReadUploadData();
        } else {
            // If we are waiting to accept the data connection, keep waiting.
            if (Comm::IsConnOpen(dataListenConn)) {
                debugs(33, 7, "wait for the client to establish a data connection");
                onDataAcceptCall = call;
                // TODO: Add connect timeout for passive connections listener?
                // TODO: Remember server response so that we can forward it?
            } else {
                // Either the connection was establised and closed after the
                // data was transferred OR we failed to establish an active
                // data connection and already sent the error to the client.
                // In either case, there is nothing more to do.
                debugs(33, 7, "done with data OR active connection failed");
            }
            return;
        }
    }

    MemBuf mb;
    mb.init();
    Ftp::PrintReply(mb, reply);

    debugs(9, 2, "FTP Client " << clientConnection);
    debugs(9, 2, "FTP Client REPLY:\n---------\n" << mb.buf <<
           "\n----------");

    Comm::Write(clientConnection, &mb, call);
}

static void
Ftp::PrintReply(MemBuf &mb, const HttpReply *reply, const char *const)
{
    const HttpHeader &header = reply->header;

    HttpHeaderPos pos = HttpHeaderInitPos;
    while (const HttpHeaderEntry *e = header.getEntry(&pos)) {
        if (e->id == Http::HdrType::FTP_PRE) {
            String raw;
            if (httpHeaderParseQuotedString(e->value.rawBuf(), e->value.size(), &raw))
                mb.appendf("%s\r\n", raw.termedBuf());
        }
    }

    if (header.has(Http::HdrType::FTP_STATUS)) {
        const char *reason = header.getStr(Http::HdrType::FTP_REASON);
        mb.appendf("%i %s\r\n", header.getInt(Http::HdrType::FTP_STATUS),
                   (reason ? reason : 0));
    }
}

void
Ftp::Server::wroteEarlyReply(const CommIoCbParams &io)
{
    if (io.flag == Comm::ERR_CLOSING)
        return;

    if (io.flag != Comm::OK) {
        debugs(33, 3, "FTP reply writing failed: " << xstrerr(io.xerrno));
        io.conn->close();
        return;
    }

    Http::StreamPointer context = pipeline.front();
    if (context != nullptr && context->http) {
        context->http->out.size += io.size;
        context->http->out.headers_sz += io.size;
    }

    flags.readMore = true;
    readSomeData();
}

void
Ftp::Server::wroteReply(const CommIoCbParams &io)
{
    if (io.flag == Comm::ERR_CLOSING)
        return;

    if (io.flag != Comm::OK) {
        debugs(33, 3, "FTP reply writing failed: " << xstrerr(io.xerrno));
        io.conn->close();
        return;
    }

    Http::StreamPointer context = pipeline.front();
    assert(context->http);
    context->http->out.size += io.size;
    context->http->out.headers_sz += io.size;

    if (master->serverState == fssError) {
        debugs(33, 5, "closing on FTP server error");
        io.conn->close();
        return;
    }

    const clientStream_status_t socketState = context->socketState();
    debugs(33, 5, "FTP client stream state " << socketState);
    switch (socketState) {
    case STREAM_UNPLANNED_COMPLETE:
    case STREAM_FAILED:
        io.conn->close();
        return;

    case STREAM_NONE:
    case STREAM_COMPLETE:
        flags.readMore = true;
        changeState(fssConnected, "Ftp::Server::wroteReply");
        if (bodyParser)
            finishDechunkingRequest(false);
        context->finished();
        kick();
        return;
    }
}

bool
Ftp::Server::handleRequest(HttpRequest *request)
{
    debugs(33, 9, request);
    Must(request);

    HttpHeader &header = request->header;
    Must(header.has(Http::HdrType::FTP_COMMAND));
    String &cmd = header.findEntry(Http::HdrType::FTP_COMMAND)->value;
    Must(header.has(Http::HdrType::FTP_ARGUMENTS));
    String &params = header.findEntry(Http::HdrType::FTP_ARGUMENTS)->value;

    if (Debug::Enabled(9, 2)) {
        MemBuf mb;
        mb.init();
        request->pack(&mb);

        debugs(9, 2, "FTP Client " << clientConnection);
        debugs(9, 2, "FTP Client REQUEST:\n---------\n" << mb.buf <<
               "\n----------");
    }

    // TODO: When HttpHeader uses SBuf, change keys to SBuf
    typedef std::map<const std::string, RequestHandler> RequestHandlers;
    static RequestHandlers handlers;
    if (!handlers.size()) {
        handlers["LIST"] = &Ftp::Server::handleDataRequest;
        handlers["NLST"] = &Ftp::Server::handleDataRequest;
        handlers["MLSD"] = &Ftp::Server::handleDataRequest;
        handlers["FEAT"] = &Ftp::Server::handleFeatRequest;
        handlers["PASV"] = &Ftp::Server::handlePasvRequest;
        handlers["PORT"] = &Ftp::Server::handlePortRequest;
        handlers["RETR"] = &Ftp::Server::handleDataRequest;
        handlers["EPRT"] = &Ftp::Server::handleEprtRequest;
        handlers["EPSV"] = &Ftp::Server::handleEpsvRequest;
        handlers["CWD"] = &Ftp::Server::handleCwdRequest;
        handlers["PASS"] = &Ftp::Server::handlePassRequest;
        handlers["CDUP"] = &Ftp::Server::handleCdupRequest;
    }

    RequestHandler handler = NULL;
    if (request->method == Http::METHOD_PUT)
        handler = &Ftp::Server::handleUploadRequest;
    else {
        const RequestHandlers::const_iterator hi = handlers.find(cmd.termedBuf());
        if (hi != handlers.end())
            handler = hi->second;
    }

    if (!handler) {
        debugs(9, 7, "forwarding " << cmd << " as is, no post-processing");
        return true;
    }

    return (this->*handler)(cmd, params);
}

/// Called to parse USER command, which is required to create an HTTP request
/// wrapper. W/o request, the errors are handled by returning earlyError().
Http::Stream *
Ftp::Server::handleUserRequest(const SBuf &, SBuf &params)
{
    if (params.isEmpty())
        return earlyError(EarlyErrorKind::MissingUsername);

    // find the [end of] user name
    const SBuf::size_type eou = params.rfind('@');
    if (eou == SBuf::npos || eou + 1 >= params.length())
        return earlyError(EarlyErrorKind::MissingHost);

    // Determine the intended destination.
    host = params.substr(eou + 1, params.length());
    // If we can parse it as raw IPv6 address, then surround with "[]".
    // Otherwise (domain, IPv4, [bracketed] IPv6, garbage, etc), use as is.
    if (host.find(':') != SBuf::npos) {
        const Ip::Address ipa(host.c_str());
        if (!ipa.isAnyAddr()) {
            char ipBuf[MAX_IPSTRLEN];
            ipa.toHostStr(ipBuf, MAX_IPSTRLEN);
            host = ipBuf;
        }
    }

    // const SBuf login = params.substr(0, eou);
    params.chop(0, eou); // leave just the login part for the peer

    SBuf oldUri;
    if (master->clientReadGreeting)
        oldUri = uri;

    master->workingDir.clear();
    calcUri(NULL);

    if (!master->clientReadGreeting) {
        debugs(9, 3, "set URI to " << uri);
    } else if (oldUri.caseCmp(uri) == 0) {
        debugs(9, 5, "kept URI as " << oldUri);
    } else {
        debugs(9, 3, "reset URI from " << oldUri << " to " << uri);
        closeDataConnection();
        unpinConnection(true); // close control connection to peer
        resetLogin("URI reset");
    }

    return NULL; // no early errors
}

bool
Ftp::Server::handleFeatRequest(String &, String &)
{
    changeState(fssHandleFeat, "handleFeatRequest");
    return true;
}

bool
Ftp::Server::handlePasvRequest(String &, String &params)
{
    if (gotEpsvAll) {
        setReply(500, "Bad PASV command");
        return false;
    }

    if (params.size() > 0) {
        setReply(501, "Unexpected parameter");
        return false;
    }

    changeState(fssHandlePasv, "handlePasvRequest");
    // no need to fake PASV request via setDataCommand() in true PASV case
    return true;
}

/// [Re]initializes dataConn for active data transfers. Does not connect.
bool
Ftp::Server::createDataConnection(Ip::Address cltAddr)
{
    assert(clientConnection != NULL);
    assert(!clientConnection->remote.isAnyAddr());

    if (cltAddr != clientConnection->remote) {
        debugs(33, 2, "rogue PORT " << cltAddr << " request? ctrl: " << clientConnection->remote);
        // Closing the control connection would not help with attacks because
        // the client is evidently able to connect to us. Besides, closing
        // makes retrials easier for the client and more damaging to us.
        setReply(501, "Prohibited parameter value");
        return false;
    }

    closeDataConnection();

    Comm::ConnectionPointer conn = new Comm::Connection();
    conn->flags |= COMM_DOBIND;

    if (clientConnection->flags & COMM_INTERCEPTION) {
        // In the case of NAT interception conn->local value is not set
        // because the TCP stack will automatically pick correct source
        // address for the data connection. We must only ensure that IP
        // version matches client's address.
        conn->local.setAnyAddr();

        if (cltAddr.isIPv4())
            conn->local.setIPv4();

        conn->remote = cltAddr;
    } else {
        // In the case of explicit-proxy the local IP of the control connection
        // is the Squid IP the client is knowingly talking to.
        //
        // In the case of TPROXY the IP address of the control connection is
        // server IP the client is connecting to, it can be spoofed by Squid.
        //
        // In both cases some clients may refuse to accept data connections if
        // these control connectin local-IP's are not used.
        conn->setAddrs(clientConnection->local, cltAddr);

        // Using non-local addresses in TPROXY mode requires appropriate socket option.
        if (clientConnection->flags & COMM_TRANSPARENT)
            conn->flags |= COMM_TRANSPARENT;
    }

    // RFC 959 requires active FTP connections to originate from port 20
    // but that would preclude us from supporting concurrent transfers! (XXX?)
    conn->local.port(0);

    debugs(9, 3, "will actively connect from " << conn->local << " to " <<
           conn->remote);

    dataConn = conn;
    uploadAvailSize = 0;
    return true;
}

bool
Ftp::Server::handlePortRequest(String &, String &params)
{
    // TODO: Should PORT errors trigger closeDataConnection() cleanup?

    if (gotEpsvAll) {
        setReply(500, "Rejecting PORT after EPSV ALL");
        return false;
    }

    if (!params.size()) {
        setReply(501, "Missing parameter");
        return false;
    }

    Ip::Address cltAddr;
    if (!Ftp::ParseIpPort(params.termedBuf(), NULL, cltAddr)) {
        setReply(501, "Invalid parameter");
        return false;
    }

    if (!createDataConnection(cltAddr))
        return false;

    changeState(fssHandlePort, "handlePortRequest");
    setDataCommand();
    return true; // forward our fake PASV request
}

bool
Ftp::Server::handleDataRequest(String &, String &)
{
    if (!checkDataConnPre())
        return false;

    master->userDataDone = 0;
    originDataDownloadAbortedOnError = false;

    changeState(fssHandleDataRequest, "handleDataRequest");

    return true;
}

bool
Ftp::Server::handleUploadRequest(String &, String &)
{
    if (!checkDataConnPre())
        return false;

    if (Config.accessList.forceRequestBodyContinuation) {
        ClientHttpRequest *http = pipeline.front()->http;
        HttpRequest *request = http->request;
        ACLFilledChecklist bodyContinuationCheck(Config.accessList.forceRequestBodyContinuation, request, NULL);
        bodyContinuationCheck.al = http->al;
        bodyContinuationCheck.syncAle(request, http->log_uri);
        if (bodyContinuationCheck.fastCheck().allowed()) {
            request->forcedBodyContinuation = true;
            if (checkDataConnPost()) {
                // Write control Msg
                writeEarlyReply(150, "Data connection opened");
                maybeReadUploadData();
            } else {
                // wait for acceptDataConnection but tell it to call wroteEarlyReply
                // after writing "150 Data connection opened"
                typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
                AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, Ftp::Server::wroteEarlyReply);
                onDataAcceptCall = call;
            }
        }
    }

    changeState(fssHandleUploadRequest, "handleDataRequest");

    return true;
}

bool
Ftp::Server::handleEprtRequest(String &, String &params)
{
    debugs(9, 3, "Process an EPRT " << params);

    if (gotEpsvAll) {
        setReply(500, "Rejecting EPRT after EPSV ALL");
        return false;
    }

    if (!params.size()) {
        setReply(501, "Missing parameter");
        return false;
    }

    Ip::Address cltAddr;
    if (!Ftp::ParseProtoIpPort(params.termedBuf(), cltAddr)) {
        setReply(501, "Invalid parameter");
        return false;
    }

    if (!createDataConnection(cltAddr))
        return false;

    changeState(fssHandleEprt, "handleEprtRequest");
    setDataCommand();
    return true; // forward our fake PASV request
}

bool
Ftp::Server::handleEpsvRequest(String &, String &params)
{
    debugs(9, 3, "Process an EPSV command with params: " << params);
    if (params.size() <= 0) {
        // treat parameterless EPSV as "use the protocol of the ctrl conn"
    } else if (params.caseCmp("ALL") == 0) {
        setReply(200, "EPSV ALL ok");
        gotEpsvAll = true;
        return false;
    } else if (params.cmp("2") == 0) {
        if (!Ip::EnableIpv6) {
            setReply(522, "Network protocol not supported, use (1)");
            return false;
        }
    } else if (params.cmp("1") != 0) {
        setReply(501, "Unsupported EPSV parameter");
        return false;
    }

    changeState(fssHandleEpsv, "handleEpsvRequest");
    setDataCommand();
    return true; // forward our fake PASV request
}

bool
Ftp::Server::handleCwdRequest(String &, String &)
{
    changeState(fssHandleCwd, "handleCwdRequest");
    return true;
}

bool
Ftp::Server::handlePassRequest(String &, String &)
{
    changeState(fssHandlePass, "handlePassRequest");
    return true;
}

bool
Ftp::Server::handleCdupRequest(String &, String &)
{
    changeState(fssHandleCdup, "handleCdupRequest");
    return true;
}

// Convert user PORT, EPRT, PASV, or EPSV data command to Squid PASV command.
// Squid FTP client decides what data command to use with peers.
void
Ftp::Server::setDataCommand()
{
    ClientHttpRequest *const http = pipeline.front()->http;
    assert(http != NULL);
    HttpRequest *const request = http->request;
    assert(request != NULL);
    HttpHeader &header = request->header;
    header.delById(Http::HdrType::FTP_COMMAND);
    header.putStr(Http::HdrType::FTP_COMMAND, "PASV");
    header.delById(Http::HdrType::FTP_ARGUMENTS);
    header.putStr(Http::HdrType::FTP_ARGUMENTS, "");
    debugs(9, 5, "client data command converted to fake PASV");
}

/// check that client data connection is ready for future I/O or at least
/// has a chance of becoming ready soon.
bool
Ftp::Server::checkDataConnPre()
{
    if (Comm::IsConnOpen(dataConn))
        return true;

    if (Comm::IsConnOpen(dataListenConn)) {
        // We are still waiting for a client to connect to us after PASV.
        // Perhaps client's data conn handshake has not reached us yet.
        // After we talk to the server, checkDataConnPost() will recheck.
        debugs(33, 3, "expecting clt data conn " << dataListenConn);
        return true;
    }

    if (!dataConn || dataConn->remote.isAnyAddr()) {
        debugs(33, 5, "missing " << dataConn);
        // TODO: use client address and default port instead.
        setReply(425, "Use PORT or PASV first");
        return false;
    }

    // active transfer: open a data connection from Squid to client
    typedef CommCbMemFunT<Server, CommConnectCbParams> Dialer;
    connector = JobCallback(17, 3, Dialer, this, Ftp::Server::connectedForData);
    Comm::ConnOpener *cs = new Comm::ConnOpener(dataConn, connector,
            Config.Timeout.connect);
    AsyncJob::Start(cs);
    return false; // ConnStateData::processFtpRequest waits handleConnectDone
}

/// Check that client data connection is ready for immediate I/O.
bool
Ftp::Server::checkDataConnPost() const
{
    if (!Comm::IsConnOpen(dataConn)) {
        debugs(33, 3, "missing client data conn: " << dataConn);
        return false;
    }
    return true;
}

/// Done establishing a data connection to the user.
void
Ftp::Server::connectedForData(const CommConnectCbParams &params)
{
    connector = NULL;

    if (params.flag != Comm::OK) {
        /* it might have been a timeout with a partially open link */
        if (params.conn != NULL)
            params.conn->close();
        setReply(425, "Cannot open data connection.");
        Http::StreamPointer context = pipeline.front();
        Must(context->http);
        Must(context->http->storeEntry() != NULL);
    } else {
        Must(dataConn == params.conn);
        Must(Comm::IsConnOpen(params.conn));
        fd_note(params.conn->fd, "active client ftp data");
    }

    doProcessRequest();
}

void
Ftp::Server::setReply(const int code, const char *msg)
{
    Http::StreamPointer context = pipeline.front();
    ClientHttpRequest *const http = context->http;
    assert(http != NULL);
    assert(http->storeEntry() == NULL);

    HttpReply *const reply = Ftp::HttpReplyWrapper(code, msg, Http::scNoContent, 0);

    setLogUri(http, urlCanonicalClean(http->request));

    clientStreamNode *const node = context->getClientReplyContext();
    clientReplyContext *const repContext =
        dynamic_cast<clientReplyContext *>(node->data.getRaw());
    assert(repContext != NULL);

    RequestFlags reqFlags;
    reqFlags.cachable = false; // force releaseRequest() in storeCreateEntry()
    reqFlags.noCache = true;
    repContext->createStoreEntry(http->request->method, reqFlags);
    http->storeEntry()->replaceHttpReply(reply);
}

void
Ftp::Server::callException(const std::exception &e)
{
    debugs(33, 2, "FTP::Server job caught: " << e.what());
    closeDataConnection();
    unpinConnection(true);
    if (Comm::IsConnOpen(clientConnection))
        clientConnection->close();
    AsyncJob::callException(e);
}

void
Ftp::Server::startWaitingForOrigin()
{
    if (!isOpen()) // if we are closing, nothing to do
        return;

    debugs(33, 5, "waiting for Ftp::Client data transfer to end");
    waitingForOrigin = true;
}

void
Ftp::Server::stopWaitingForOrigin(int originStatus)
{
    Must(waitingForOrigin);
    waitingForOrigin = false;

    if (!isOpen()) // if we are closing, nothing to do
        return;

    // if we have already decided how to respond, respond now
    if (delayedReply) {
        HttpReply::Pointer reply = delayedReply;
        delayedReply = nullptr;
        writeForwardedReply(reply.getRaw());
        return; // do not completeDataDownload() after an earlier response
    }

    if (master->serverState != fssHandleDataRequest)
        return;

    // completeDataDownload() could be waitingForOrigin in fssHandleDataRequest
    // Depending on which side has finished downloading first, either trust
    // master->userDataDone status or set originDataDownloadAbortedOnError:
    if (master->userDataDone) {
        // We finished downloading before Ftp::Client. Most likely, the
        // adaptation shortened the origin response or we hit an error.
        // Our status (stored in master->userDataDone) is more informative.
        // Use master->userDataDone; avoid originDataDownloadAbortedOnError.
        completeDataDownload();
    } else {
        debugs(33, 5, "too early to write the response");
        // Ftp::Client naturally finished downloading before us. Set
        // originDataDownloadAbortedOnError to overwrite future
        // master->userDataDone and relay Ftp::Client error, if there was
        // any, to the user.
        originDataDownloadAbortedOnError = (originStatus >= 400);
    }
}

void Ftp::Server::userDataCompletionCheckpoint(int finalStatusCode)
{
    Must(!master->userDataDone);
    master->userDataDone = finalStatusCode;

    if (bodyParser)
        finishDechunkingRequest(false);

    if (waitingForOrigin) {
        // The completeDataDownload() is not called here unconditionally
        // because we want to signal the FTP user that we are not fully
        // done processing its data stream, even though all data bytes
        // have been sent or received already.
        debugs(33, 5, "Transferring from FTP server is not complete");
        return;
    }

    // Adjust our reply if the server aborted with an error before we are done.
    if (master->userDataDone == 226 && originDataDownloadAbortedOnError) {
        debugs(33, 5, "Transferring from FTP server terminated with an error, adjust status code");
        master->userDataDone = 451;
    }
    completeDataDownload();
}

void Ftp::Server::completeDataDownload()
{
    writeCustomReply(master->userDataDone, master->userDataDone == 226 ? "Transfer complete" : "Server error; transfer aborted");
    closeDataConnection();
}

/// Whether Squid FTP Relay supports a named feature (e.g., a command).
static bool
Ftp::SupportedCommand(const SBuf &name)
{
    static std::set<SBuf> BlackList;
    if (BlackList.empty()) {
        /* Add FTP commands that Squid cannot relay correctly. */

        // We probably do not support AUTH TLS.* and AUTH SSL,
        // but let's disclaim all AUTH support to KISS, for now.
        BlackList.insert(cmdAuth());
    }

    // we claim support for all commands that we do not know about
    return BlackList.find(name) == BlackList.end();
}

