/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 09    File Transfer Protocol (FTP) */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "clients/FtpClient.h"
#include "comm/ConnOpener.h"
#include "comm/Read.h"
#include "comm/TcpAcceptor.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "ftp/Parsing.h"
#include "ip/tools.h"
#include "Mem.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "StatCounters.h"
#include "tools.h"
#include "wordlist.h"

#include <set>

namespace Ftp
{

const char *const crlf = "\r\n";

static char *
escapeIAC(const char *buf)
{
    int n;
    char *ret;
    unsigned const char *p;
    unsigned char *r;

    for (p = (unsigned const char *)buf, n = 1; *p; ++n, ++p)
        if (*p == 255)
            ++n;

    ret = (char *)xmalloc(n);

    for (p = (unsigned const char *)buf, r=(unsigned char *)ret; *p; ++p) {
        *r = *p;
        ++r;

        if (*p == 255) {
            *r = 255;
            ++r;
        }
    }

    *r = '\0';
    ++r;
    assert((r - (unsigned char *)ret) == n );
    return ret;
}

/* Ftp::Channel */

/// configures the channel with a descriptor and registers a close handler
void
Ftp::Channel::opened(const Comm::ConnectionPointer &newConn,
                     const AsyncCall::Pointer &aCloser)
{
    assert(!Comm::IsConnOpen(conn));
    assert(closer == NULL);

    assert(Comm::IsConnOpen(newConn));
    assert(aCloser != NULL);

    conn = newConn;
    closer = aCloser;
    comm_add_close_handler(conn->fd, closer);
}

/// planned close: removes the close handler and calls comm_close
void
Ftp::Channel::close()
{
    // channels with active listeners will be closed when the listener handler dies.
    if (Comm::IsConnOpen(conn)) {
        comm_remove_close_handler(conn->fd, closer);
        conn->close(); // we do not expect to be called back
    }
    clear();
}

void
Ftp::Channel::forget()
{
    if (Comm::IsConnOpen(conn)) {
        commUnsetConnTimeout(conn);
        comm_remove_close_handler(conn->fd, closer);
    }
    clear();
}

void
Ftp::Channel::clear()
{
    conn = NULL;
    closer = NULL;
}

/* Ftp::CtrlChannel */

Ftp::CtrlChannel::CtrlChannel():
    buf(NULL),
    size(0),
    offset(0),
    message(NULL),
    last_command(NULL),
    last_reply(NULL),
    replycode(0)
{
    buf = static_cast<char*>(memAllocBuf(4096, &size));
}

Ftp::CtrlChannel::~CtrlChannel()
{
    memFreeBuf(size, buf);
    if (message)
        wordlistDestroy(&message);
    safe_free(last_command);
    safe_free(last_reply);
}

/* Ftp::DataChannel */

Ftp::DataChannel::DataChannel():
    readBuf(NULL),
    host(NULL),
    port(0),
    read_pending(false)
{
}

Ftp::DataChannel::~DataChannel()
{
    delete readBuf;
}

void
Ftp::DataChannel::addr(const Ip::Address &import)
{
    static char addrBuf[MAX_IPSTRLEN];
    import.toStr(addrBuf, sizeof(addrBuf));
    xfree(host);
    host = xstrdup(addrBuf);
    port = import.port();
}

/* Ftp::Client */

Ftp::Client::Client(FwdState *fwdState):
    AsyncJob("Ftp::Client"),
    ::Client(fwdState),
     ctrl(),
     data(),
     state(BEGIN),
     old_request(NULL),
     old_reply(NULL),
     shortenReadTimeout(false)
{
    ++statCounter.server.all.requests;
    ++statCounter.server.ftp.requests;

    ctrl.last_command = xstrdup("Connect to server");

    typedef CommCbMemFunT<Client, CommCloseCbParams> Dialer;
    const AsyncCall::Pointer closer = JobCallback(9, 5, Dialer, this,
                                      Ftp::Client::ctrlClosed);
    ctrl.opened(fwdState->serverConnection(), closer);
}

Ftp::Client::~Client()
{
    if (data.opener != NULL) {
        data.opener->cancel("Ftp::Client destructed");
        data.opener = NULL;
    }
    data.close();

    safe_free(old_request);
    safe_free(old_reply);
    fwd = NULL; // refcounted
}

void
Ftp::Client::start()
{
    scheduleReadControlReply(0);
}

void
Ftp::Client::initReadBuf()
{
    if (data.readBuf == NULL) {
        data.readBuf = new MemBuf;
        data.readBuf->init(4096, SQUID_TCP_SO_RCVBUF);
    }
}

/**
 * Close the FTP server connection(s). Used by serverComplete().
 */
void
Ftp::Client::closeServer()
{
    if (Comm::IsConnOpen(ctrl.conn)) {
        debugs(9, 3, "closing FTP server FD " << ctrl.conn->fd << ", this " << this);
        fwd->unregister(ctrl.conn);
        ctrl.close();
    }

    if (Comm::IsConnOpen(data.conn)) {
        debugs(9, 3, "closing FTP data FD " << data.conn->fd << ", this " << this);
        data.close();
    }

    debugs(9, 3, "FTP ctrl and data connections closed. this " << this);
}

/**
 * Did we close all FTP server connection(s)?
 *
 \retval true  Both server control and data channels are closed. And not waiting for a new data connection to open.
 \retval false Either control channel or data is still active.
 */
bool
Ftp::Client::doneWithServer() const
{
    return !Comm::IsConnOpen(ctrl.conn) && !Comm::IsConnOpen(data.conn);
}

void
Ftp::Client::failed(err_type error, int xerrno, ErrorState *err)
{
    debugs(9, 3, "entry-null=" << (entry?entry->isEmpty():0) << ", entry=" << entry);

    const char *command, *reply;
    ErrorState *ftperr;

    if (err) {
        debugs(9, 6, "error=" << err->type << ", code=" << xerrno <<
               ", status=" << err->httpStatus);
        error = err->type;
        ftperr = err;
    } else {
        Http::StatusCode httpStatus = failedHttpStatus(error);
        ftperr = new ErrorState(error, httpStatus, fwd->request);
    }

    ftperr->xerrno = xerrno;

    ftperr->ftp.server_msg = ctrl.message;
    ctrl.message = NULL;

    if (old_request)
        command = old_request;
    else
        command = ctrl.last_command;

    if (command && strncmp(command, "PASS", 4) == 0)
        command = "PASS <yourpassword>";

    if (old_reply)
        reply = old_reply;
    else
        reply = ctrl.last_reply;

    if (command)
        ftperr->ftp.request = xstrdup(command);

    if (reply)
        ftperr->ftp.reply = xstrdup(reply);

    if (!err) {
        fwd->request->detailError(error, xerrno);
        fwd->fail(ftperr);
        closeServer(); // we failed, so no serverComplete()
    }
}

Http::StatusCode
Ftp::Client::failedHttpStatus(err_type &error)
{
    if (error == ERR_NONE)
        error = ERR_FTP_FAILURE;
    return error == ERR_READ_TIMEOUT ? Http::scGatewayTimeout :
           Http::scBadGateway;
}

/**
 * DPW 2007-04-23
 * Looks like there are no longer anymore callers that set
 * buffered_ok=1.  Perhaps it can be removed at some point.
 */
void
Ftp::Client::scheduleReadControlReply(int buffered_ok)
{
    debugs(9, 3, ctrl.conn);

    if (buffered_ok && ctrl.offset > 0) {
        /* We've already read some reply data */
        handleControlReply();
    } else {
        /*
         * Cancel the timeout on the Data socket (if any) and
         * establish one on the control socket.
         */
        if (Comm::IsConnOpen(data.conn)) {
            commUnsetConnTimeout(data.conn);
        }

        const time_t tout = shortenReadTimeout ?
                            min(Config.Timeout.connect, Config.Timeout.read):
                            Config.Timeout.read;
        shortenReadTimeout = false; // we only need to do this once, after PASV

        typedef CommCbMemFunT<Client, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall = JobCallback(9, 5, TimeoutDialer, this, Ftp::Client::timeout);
        commSetConnTimeout(ctrl.conn, tout, timeoutCall);

        typedef CommCbMemFunT<Client, CommIoCbParams> Dialer;
        AsyncCall::Pointer reader = JobCallback(9, 5, Dialer, this, Ftp::Client::readControlReply);
        comm_read(ctrl.conn, ctrl.buf + ctrl.offset, ctrl.size - ctrl.offset, reader);
    }
}

void
Ftp::Client::readControlReply(const CommIoCbParams &io)
{
    debugs(9, 3, "FD " << io.fd << ", Read " << io.size << " bytes");

    if (io.size > 0) {
        kb_incr(&(statCounter.server.all.kbytes_in), io.size);
        kb_incr(&(statCounter.server.ftp.kbytes_in), io.size);
    }

    if (io.flag == Comm::ERR_CLOSING)
        return;

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted during control reply read");
        return;
    }

    assert(ctrl.offset < ctrl.size);

    if (io.flag == Comm::OK && io.size > 0) {
        fd_bytes(io.fd, io.size, FD_READ);
    }

    if (io.flag != Comm::OK) {
        debugs(50, ignoreErrno(io.xerrno) ? 3 : DBG_IMPORTANT,
               "FTP control reply read error: " << xstrerr(io.xerrno));

        if (ignoreErrno(io.xerrno)) {
            scheduleReadControlReply(0);
        } else {
            failed(ERR_READ_ERROR, io.xerrno);
            /* failed closes ctrl.conn and frees ftpState */
        }
        return;
    }

    if (io.size == 0) {
        if (entry->store_status == STORE_PENDING) {
            failed(ERR_FTP_FAILURE, 0);
            /* failed closes ctrl.conn and frees ftpState */
            return;
        }

        /* XXX this may end up having to be serverComplete() .. */
        abortTransaction("zero control reply read");
        return;
    }

    unsigned int len =io.size + ctrl.offset;
    ctrl.offset = len;
    assert(len <= ctrl.size);
    if (Comm::IsConnOpen(ctrl.conn))
        commUnsetConnTimeout(ctrl.conn); // we are done waiting for ctrl reply
    handleControlReply();
}

void
Ftp::Client::handleControlReply()
{
    debugs(9, 3, status());

    size_t bytes_used = 0;
    wordlistDestroy(&ctrl.message);

    if (!parseControlReply(bytes_used)) {
        /* didn't get complete reply yet */

        if (ctrl.offset == ctrl.size) {
            ctrl.buf = static_cast<char*>(memReallocBuf(ctrl.buf, ctrl.size << 1, &ctrl.size));
        }

        scheduleReadControlReply(0);
        return;
    }

    assert(ctrl.message); // the entire FTP server response, line by line
    assert(ctrl.replycode >= 0); // FTP status code (from the last line)
    assert(ctrl.last_reply); // FTP reason (from the last line)

    if (ctrl.offset == bytes_used) {
        /* used it all up */
        ctrl.offset = 0;
    } else {
        /* Got some data past the complete reply */
        assert(bytes_used < ctrl.offset);
        ctrl.offset -= bytes_used;
        memmove(ctrl.buf, ctrl.buf + bytes_used, ctrl.offset);
    }

    debugs(9, 3, "state=" << state << ", code=" << ctrl.replycode);
}

bool
Ftp::Client::handlePasvReply(Ip::Address &srvAddr)
{
    int code = ctrl.replycode;
    char *buf;
    debugs(9, 3, status());

    if (code != 227) {
        debugs(9, 2, "PASV not supported by remote end");
        return false;
    }

    /*  227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).  */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debugs(9, 5, "scanning: " << ctrl.last_reply);

    buf = ctrl.last_reply + strcspn(ctrl.last_reply, "0123456789");

    const char *forceIp = Config.Ftp.sanitycheck ?
                          fd_table[ctrl.conn->fd].ipaddr : NULL;
    if (!Ftp::ParseIpPort(buf, forceIp, srvAddr)) {
        debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
               ctrl.conn->remote << ": " << ctrl.last_reply);
        return false;
    }

    data.addr(srvAddr);

    return true;
}

bool
Ftp::Client::handleEpsvReply(Ip::Address &remoteAddr)
{
    int code = ctrl.replycode;
    char *buf;
    debugs(9, 3, status());

    if (code != 229 && code != 522) {
        if (code == 200) {
            /* handle broken servers (RFC 2428 says OK code for EPSV MUST be 229 not 200) */
            /* vsftpd for one send '200 EPSV ALL ok.' without even port info.
             * Its okay to re-send EPSV 1/2 but nothing else. */
            debugs(9, DBG_IMPORTANT, "Broken FTP Server at " << ctrl.conn->remote << ". Wrong accept code for EPSV");
        } else {
            debugs(9, 2, "EPSV not supported by remote end");
        }
        return sendPassive();
    }

    if (code == 522) {
        /* Peer responded with a list of supported methods:
         *   522 Network protocol not supported, use (1)
         *   522 Network protocol not supported, use (1,2)
         *   522 Network protocol not supported, use (2)
         * TODO: Handle the (1,2) case which may happen after EPSV ALL. Close
         * data + control without self-destructing and re-open from scratch.
         */
        debugs(9, 5, "scanning: " << ctrl.last_reply);
        buf = ctrl.last_reply;
        while (buf != NULL && *buf != '\0' && *buf != '\n' && *buf != '(')
            ++buf;
        if (buf != NULL && *buf == '\n')
            ++buf;

        if (buf == NULL || *buf == '\0') {
            /* handle broken server (RFC 2428 says MUST specify supported protocols in 522) */
            debugs(9, DBG_IMPORTANT, "Broken FTP Server at " << ctrl.conn->remote << ". 522 error missing protocol negotiation hints");
            return sendPassive();
        } else if (strcmp(buf, "(1)") == 0) {
            state = SENT_EPSV_2; /* simulate having sent and failed EPSV 2 */
            return sendPassive();
        } else if (strcmp(buf, "(2)") == 0) {
            if (Ip::EnableIpv6) {
                /* If server only supports EPSV 2 and we have already tried that. Go straight to EPRT */
                if (state == SENT_EPSV_2) {
                    return sendEprt();
                } else {
                    /* or try the next Passive mode down the chain. */
                    return sendPassive();
                }
            } else {
                /* Server only accept EPSV in IPv6 traffic. */
                state = SENT_EPSV_1; /* simulate having sent and failed EPSV 1 */
                return sendPassive();
            }
        } else {
            /* handle broken server (RFC 2428 says MUST specify supported protocols in 522) */
            debugs(9, DBG_IMPORTANT, "WARNING: Server at " << ctrl.conn->remote << " sent unknown protocol negotiation hint: " << buf);
            return sendPassive();
        }
        failed(ERR_FTP_FAILURE, 0);
        return false;
    }

    /*  229 Entering Extended Passive Mode (|||port|) */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debugs(9, 5, "scanning: " << ctrl.last_reply);

    buf = ctrl.last_reply + strcspn(ctrl.last_reply, "(");

    char h1, h2, h3, h4;
    unsigned short port;
    int n = sscanf(buf, "(%c%c%c%hu%c)", &h1, &h2, &h3, &port, &h4);

    if (n < 4 || h1 != h2 || h1 != h3 || h1 != h4) {
        debugs(9, DBG_IMPORTANT, "Invalid EPSV reply from " <<
               ctrl.conn->remote << ": " <<
               ctrl.last_reply);

        return sendPassive();
    }

    if (0 == port) {
        debugs(9, DBG_IMPORTANT, "Unsafe EPSV reply from " <<
               ctrl.conn->remote << ": " <<
               ctrl.last_reply);

        return sendPassive();
    }

    if (Config.Ftp.sanitycheck) {
        if (port < 1024) {
            debugs(9, DBG_IMPORTANT, "Unsafe EPSV reply from " <<
                   ctrl.conn->remote << ": " <<
                   ctrl.last_reply);

            return sendPassive();
        }
    }

    remoteAddr = ctrl.conn->remote;
    remoteAddr.port(port);
    data.addr(remoteAddr);
    return true;
}

// FTP clients do not support EPRT and PORT commands yet.
// The Ftp::Client::sendEprt() will fail because of the unimplemented
// openListenSocket() or sendPort() methods
bool
Ftp::Client::sendEprt()
{
    if (!Config.Ftp.eprt) {
        /* Disabled. Switch immediately to attempting old PORT command. */
        debugs(9, 3, "EPRT disabled by local administrator");
        return sendPort();
    }

    debugs(9, 3, status());

    if (!openListenSocket()) {
        failed(ERR_FTP_FAILURE, 0);
        return false;
    }

    debugs(9, 3, "Listening for FTP data connection with FD " << data.conn);
    if (!Comm::IsConnOpen(data.conn)) {
        // TODO: Set error message.
        failed(ERR_FTP_FAILURE, 0);
        return false;
    }

    static MemBuf mb;
    mb.reset();
    char buf[MAX_IPSTRLEN];
    /* RFC 2428 defines EPRT as IPv6 equivalent to IPv4 PORT command. */
    /* Which can be used by EITHER protocol. */
    debugs(9, 3, "Listening for FTP data connection on port" << comm_local_port(data.conn->fd) << " or port?" << data.conn->local.port());
    mb.Printf("EPRT |%d|%s|%d|%s",
              ( data.conn->local.isIPv6() ? 2 : 1 ),
              data.conn->local.toStr(buf,MAX_IPSTRLEN),
              comm_local_port(data.conn->fd), Ftp::crlf );

    state = SENT_EPRT;
    writeCommand(mb.content());
    return true;
}

bool
Ftp::Client::sendPort()
{
    failed(ERR_FTP_FAILURE, 0);
    return false;
}

bool
Ftp::Client::sendPassive()
{
    debugs(9, 3, status());

    /** \par
      * Checks for EPSV ALL special conditions:
      * If enabled to be sent, squid MUST NOT request any other connect methods.
      * If 'ALL' is sent and fails the entire FTP Session fails.
      * NP: By my reading exact EPSV protocols maybe attempted, but only EPSV method. */
    if (Config.Ftp.epsv_all && state == SENT_EPSV_1 ) {
        // We are here because the last "EPSV 1" failed, but because of epsv_all
        // no other method allowed.
        debugs(9, DBG_IMPORTANT, "FTP does not allow PASV method after 'EPSV ALL' has been sent.");
        failed(ERR_FTP_FAILURE, 0);
        return false;
    }

    /// Closes any old FTP-Data connection which may exist. */
    data.close();

    /** \par
      * Checks for previous EPSV/PASV failures on this server/session.
      * Diverts to EPRT immediately if they are not working. */
    if (!Config.Ftp.passive || state == SENT_PASV) {
        sendEprt();
        return true;
    }

    static MemBuf mb;
    mb.reset();
    /** \par
      * Send EPSV (ALL,2,1) or PASV on the control channel.
      *
      *  - EPSV ALL  is used if enabled.
      *  - EPSV 2    is used if ALL is disabled and IPv6 is available and ctrl channel is IPv6.
      *  - EPSV 1    is used if EPSV 2 (IPv6) fails or is not available or ctrl channel is IPv4.
      *  - PASV      is used if EPSV 1 fails.
      */
    switch (state) {
    case SENT_EPSV_ALL: /* EPSV ALL resulted in a bad response. Try ther EPSV methods. */
        if (ctrl.conn->local.isIPv6()) {
            debugs(9, 5, "FTP Channel is IPv6 (" << ctrl.conn->remote << ") attempting EPSV 2 after EPSV ALL has failed.");
            mb.Printf("EPSV 2%s", Ftp::crlf);
            state = SENT_EPSV_2;
            break;
        }
    // else fall through to skip EPSV 2

    case SENT_EPSV_2: /* EPSV IPv6 failed. Try EPSV IPv4 */
        if (ctrl.conn->local.isIPv4()) {
            debugs(9, 5, "FTP Channel is IPv4 (" << ctrl.conn->remote << ") attempting EPSV 1 after EPSV ALL has failed.");
            mb.Printf("EPSV 1%s", Ftp::crlf);
            state = SENT_EPSV_1;
            break;
        } else if (Config.Ftp.epsv_all) {
            debugs(9, DBG_IMPORTANT, "FTP does not allow PASV method after 'EPSV ALL' has been sent.");
            failed(ERR_FTP_FAILURE, 0);
            return false;
        }
    // else fall through to skip EPSV 1

    case SENT_EPSV_1: /* EPSV options exhausted. Try PASV now. */
        debugs(9, 5, "FTP Channel (" << ctrl.conn->remote << ") rejects EPSV connection attempts. Trying PASV instead.");
        mb.Printf("PASV%s", Ftp::crlf);
        state = SENT_PASV;
        break;

    default: {
        bool doEpsv = true;
        if (Config.accessList.ftp_epsv) {
            ACLFilledChecklist checklist(Config.accessList.ftp_epsv, fwd->request, NULL);
            doEpsv = (checklist.fastCheck() == ACCESS_ALLOWED);
        }
        if (!doEpsv) {
            debugs(9, 5, "EPSV support manually disabled. Sending PASV for FTP Channel (" << ctrl.conn->remote <<")");
            mb.Printf("PASV%s", Ftp::crlf);
            state = SENT_PASV;
        } else if (Config.Ftp.epsv_all) {
            debugs(9, 5, "EPSV ALL manually enabled. Attempting with FTP Channel (" << ctrl.conn->remote <<")");
            mb.Printf("EPSV ALL%s", Ftp::crlf);
            state = SENT_EPSV_ALL;
        } else {
            if (ctrl.conn->local.isIPv6()) {
                debugs(9, 5, "FTP Channel (" << ctrl.conn->remote << "). Sending default EPSV 2");
                mb.Printf("EPSV 2%s", Ftp::crlf);
                state = SENT_EPSV_2;
            }
            if (ctrl.conn->local.isIPv4()) {
                debugs(9, 5, "Channel (" << ctrl.conn->remote <<"). Sending default EPSV 1");
                mb.Printf("EPSV 1%s", Ftp::crlf);
                state = SENT_EPSV_1;
            }
        }
        break;
    }
    }

    if (ctrl.message)
        wordlistDestroy(&ctrl.message);
    ctrl.message = NULL; //No message to return to client.
    ctrl.offset = 0; //reset readed response, to make room read the next response

    writeCommand(mb.content());

    shortenReadTimeout = true;
    return true;
}

void
Ftp::Client::connectDataChannel()
{
    safe_free(ctrl.last_command);

    safe_free(ctrl.last_reply);

    ctrl.last_command = xstrdup("Connect to server data port");

    // Generate a new data channel descriptor to be opened.
    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->setAddrs(ctrl.conn->local, data.host);
    conn->local.port(0);
    conn->remote.port(data.port);
    conn->tos = ctrl.conn->tos;
    conn->nfmark = ctrl.conn->nfmark;

    debugs(9, 3, "connecting to " << conn->remote);

    typedef CommCbMemFunT<Client, CommConnectCbParams> Dialer;
    data.opener = JobCallback(9, 3, Dialer, this, Ftp::Client::dataChannelConnected);
    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, data.opener, Config.Timeout.connect);
    cs->setHost(data.host);
    AsyncJob::Start(cs);
}

bool
Ftp::Client::openListenSocket()
{
    return false;
}

/// creates a data channel Comm close callback
AsyncCall::Pointer
Ftp::Client::dataCloser()
{
    typedef CommCbMemFunT<Client, CommCloseCbParams> Dialer;
    return JobCallback(9, 5, Dialer, this, Ftp::Client::dataClosed);
}

/// handler called by Comm when FTP data channel is closed unexpectedly
void
Ftp::Client::dataClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, status());
    if (data.listenConn != NULL) {
        data.listenConn->close();
        data.listenConn = NULL;
        // NP clear() does the: data.fd = -1;
    }
    data.clear();
}

void
Ftp::Client::writeCommand(const char *buf)
{
    char *ebuf;
    /* trace FTP protocol communications at level 2 */
    debugs(9, 2, "ftp<< " << buf);

    if (Config.Ftp.telnet)
        ebuf = escapeIAC(buf);
    else
        ebuf = xstrdup(buf);

    safe_free(ctrl.last_command);

    safe_free(ctrl.last_reply);

    ctrl.last_command = ebuf;

    if (!Comm::IsConnOpen(ctrl.conn)) {
        debugs(9, 2, "cannot send to closing ctrl " << ctrl.conn);
        // TODO: assert(ctrl.closer != NULL);
        return;
    }

    typedef CommCbMemFunT<Client, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(9, 5, Dialer, this,
                                          Ftp::Client::writeCommandCallback);
    Comm::Write(ctrl.conn, ctrl.last_command, strlen(ctrl.last_command), call, NULL);

    scheduleReadControlReply(0);
}

void
Ftp::Client::writeCommandCallback(const CommIoCbParams &io)
{

    debugs(9, 5, "wrote " << io.size << " bytes");

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, FD_WRITE);
        kb_incr(&(statCounter.server.all.kbytes_out), io.size);
        kb_incr(&(statCounter.server.ftp.kbytes_out), io.size);
    }

    if (io.flag == Comm::ERR_CLOSING)
        return;

    if (io.flag) {
        debugs(9, DBG_IMPORTANT, "FTP command write error: " << io.conn << ": " << xstrerr(io.xerrno));
        failed(ERR_WRITE_ERROR, io.xerrno);
        /* failed closes ctrl.conn and frees ftpState */
        return;
    }
}

/// handler called by Comm when FTP control channel is closed unexpectedly
void
Ftp::Client::ctrlClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, status());
    ctrl.clear();
    mustStop("Ftp::Client::ctrlClosed");
}

void
Ftp::Client::timeout(const CommTimeoutCbParams &io)
{
    debugs(9, 4, io.conn << ": '" << entry->url() << "'" );

    if (abortOnBadEntry("entry went bad while waiting for a timeout"))
        return;

    failed(ERR_READ_TIMEOUT, 0);
    /* failed() closes ctrl.conn and frees ftpState */
}

const Comm::ConnectionPointer &
Ftp::Client::dataConnection() const
{
    return data.conn;
}

void
Ftp::Client::maybeReadVirginBody()
{
    // too late to read
    if (!Comm::IsConnOpen(data.conn) || fd_table[data.conn->fd].closing())
        return;

    if (data.read_pending)
        return;

    initReadBuf();

    const int read_sz = replyBodySpace(*data.readBuf, 0);

    debugs(9, 9, "FTP may read up to " << read_sz << " bytes");

    if (read_sz < 2) // see http.cc
        return;

    data.read_pending = true;

    typedef CommCbMemFunT<Client, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(9, 5,
                                      TimeoutDialer, this, Ftp::Client::timeout);
    commSetConnTimeout(data.conn, Config.Timeout.read, timeoutCall);

    debugs(9,5,"queueing read on FD " << data.conn->fd);

    typedef CommCbMemFunT<Client, CommIoCbParams> Dialer;
    entry->delayAwareRead(data.conn, data.readBuf->space(), read_sz,
                          JobCallback(9, 5, Dialer, this, Ftp::Client::dataRead));
}

void
Ftp::Client::dataRead(const CommIoCbParams &io)
{
    int j;
    int bin;

    data.read_pending = false;

    debugs(9, 3, "FD " << io.fd << " Read " << io.size << " bytes");

    if (io.size > 0) {
        kb_incr(&(statCounter.server.all.kbytes_in), io.size);
        kb_incr(&(statCounter.server.ftp.kbytes_in), io.size);
    }

    if (io.flag == Comm::ERR_CLOSING)
        return;

    assert(io.fd == data.conn->fd);

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted during dataRead");
        return;
    }

    if (io.flag == Comm::OK && io.size > 0) {
        debugs(9, 5, "appended " << io.size << " bytes to readBuf");
        data.readBuf->appended(io.size);
#if USE_DELAY_POOLS
        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(io.size);
#endif
        ++ IOStats.Ftp.reads;

        for (j = io.size - 1, bin = 0; j; ++bin)
            j >>= 1;

        ++ IOStats.Ftp.read_hist[bin];
    }

    if (io.flag != Comm::OK) {
        debugs(50, ignoreErrno(io.xerrno) ? 3 : DBG_IMPORTANT,
               "FTP data read error: " << xstrerr(io.xerrno));

        if (ignoreErrno(io.xerrno)) {
            maybeReadVirginBody();
        } else {
            failed(ERR_READ_ERROR, 0);
            /* failed closes ctrl.conn and frees ftpState */
            return;
        }
    } else if (io.size == 0) {
        debugs(9, 3, "Calling dataComplete() because io.size == 0");
        /*
         * DPW 2007-04-23
         * Dangerous curves ahead.  This call to dataComplete was
         * calling scheduleReadControlReply, handleControlReply,
         * and then ftpReadTransferDone.  If ftpReadTransferDone
         * gets unexpected status code, it closes down the control
         * socket and our FtpStateData object gets destroyed.   As
         * a workaround we no longer set the 'buffered_ok' flag in
         * the scheduleReadControlReply call.
         */
        dataComplete();
    }

    processReplyBody();
}

void
Ftp::Client::dataComplete()
{
    debugs(9, 3,status());

    /* Connection closed; transfer done. */

    /// Close data channel, if any, to conserve resources while we wait.
    data.close();

    /* expect the "transfer complete" message on the control socket */
    /*
     * DPW 2007-04-23
     * Previously, this was the only place where we set the
     * 'buffered_ok' flag when calling scheduleReadControlReply().
     * It caused some problems if the FTP server returns an unexpected
     * status code after the data command.  FtpStateData was being
     * deleted in the middle of dataRead().
     */
    /* AYJ: 2011-01-13: Bug 2581.
     * 226 status is possibly waiting in the ctrl buffer.
     * The connection will hang if we DONT send buffered_ok.
     * This happens on all transfers which can be completly sent by the
     * server before the 150 started status message is read in by Squid.
     * ie all transfers of about one packet hang.
     */
    scheduleReadControlReply(1);
}

/**
 * Quickly abort the transaction
 *
 \todo destruction should be sufficient as the destructor should cleanup,
 * including canceling close handlers
 */
void
Ftp::Client::abortTransaction(const char *reason)
{
    debugs(9, 3, "aborting transaction for " << reason <<
           "; FD " << (ctrl.conn!=NULL?ctrl.conn->fd:-1) << ", Data FD " << (data.conn!=NULL?data.conn->fd:-1) << ", this " << this);
    if (Comm::IsConnOpen(ctrl.conn)) {
        ctrl.conn->close();
        return;
    }

    fwd->handleUnregisteredServerEnd();
    mustStop("Ftp::Client::abortTransaction");
}

/**
 * Cancel the timeout on the Control socket and establish one
 * on the data socket
 */
void
Ftp::Client::switchTimeoutToDataChannel()
{
    commUnsetConnTimeout(ctrl.conn);

    typedef CommCbMemFunT<Client, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(9, 5, TimeoutDialer, this,
                                     Ftp::Client::timeout);
    commSetConnTimeout(data.conn, Config.Timeout.read, timeoutCall);
}

void
Ftp::Client::sentRequestBody(const CommIoCbParams &io)
{
    if (io.size > 0)
        kb_incr(&(statCounter.server.ftp.kbytes_out), io.size);
    ::Client::sentRequestBody(io);
}

/**
 * called after we wrote the last byte of the request body
 */
void
Ftp::Client::doneSendingRequestBody()
{
    ::Client::doneSendingRequestBody();
    debugs(9, 3, status());
    dataComplete();
    /* NP: RFC 959  3.3.  DATA CONNECTION MANAGEMENT
     * if transfer type is 'stream' call dataComplete()
     * otherwise leave open. (reschedule control channel read?)
     */
}

/// Parses FTP server control response into ctrl structure fields,
/// setting bytesUsed and returning true on success.
bool
Ftp::Client::parseControlReply(size_t &bytesUsed)
{
    char *s;
    char *sbuf;
    char *end;
    int usable;
    int complete = 0;
    wordlist *head = NULL;
    wordlist *list;
    wordlist **tail = &head;
    size_t linelen;
    debugs(9, 3, status());
    /*
     * We need a NULL-terminated buffer for scanning, ick
     */
    const size_t len = ctrl.offset;
    sbuf = (char *)xmalloc(len + 1);
    xstrncpy(sbuf, ctrl.buf, len + 1);
    end = sbuf + len - 1;

    while (*end != '\r' && *end != '\n' && end > sbuf)
        --end;

    usable = end - sbuf;

    debugs(9, 3, "usable = " << usable);

    if (usable == 0) {
        debugs(9, 3, "didn't find end of line");
        safe_free(sbuf);
        return false;
    }

    debugs(9, 3, len << " bytes to play with");
    ++end;
    s = sbuf;
    s += strspn(s, crlf);

    for (; s < end; s += strcspn(s, crlf), s += strspn(s, crlf)) {
        if (complete)
            break;

        debugs(9, 5, "s = {" << s << "}");

        linelen = strcspn(s, crlf) + 1;

        if (linelen < 2)
            break;

        if (linelen > 3)
            complete = (*s >= '0' && *s <= '9' && *(s + 3) == ' ');

        list = new wordlist();

        list->key = (char *)xmalloc(linelen);

        xstrncpy(list->key, s, linelen);

        /* trace the FTP communication chat at level 2 */
        debugs(9, 2, "ftp>> " << list->key);

        if (complete) {
            // use list->key for last_reply because s contains the new line
            ctrl.last_reply = xstrdup(list->key + 4);
            ctrl.replycode = atoi(list->key);
        }

        *tail = list;

        tail = &list->next;
    }

    bytesUsed = static_cast<size_t>(s - sbuf);
    safe_free(sbuf);

    if (!complete) {
        wordlistDestroy(&head);
        return false;
    }

    ctrl.message = head;
    assert(ctrl.replycode >= 0);
    assert(ctrl.last_reply);
    assert(ctrl.message);
    return true;
}

}; // namespace Ftp

