/*
 * DEBUG: section 09    File Transfer Protocol (FTP)
 *
 */

#include "squid.h"

#include "FtpServer.h"
#include "Mem.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "client_side.h"
#include "comm/ConnOpener.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "tools.h"
#include "wordlist.h"

namespace Ftp {

const char *const crlf = "\r\n";

/// \ingroup ServerProtocolFTPInternal
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

/// configures the channel with a descriptor and registers a close handler
void
FtpChannel::opened(const Comm::ConnectionPointer &newConn,
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
FtpChannel::close()
{
    // channels with active listeners will be closed when the listener handler dies.
    if (Comm::IsConnOpen(conn)) {
        comm_remove_close_handler(conn->fd, closer);
        conn->close(); // we do not expect to be called back
    }
    clear();
}

void
FtpChannel::forget()
{
    if (Comm::IsConnOpen(conn))
        comm_remove_close_handler(conn->fd, closer);
    clear();
}

void
FtpChannel::clear()
{
    conn = NULL;
    closer = NULL;
}

ServerStateData::ServerStateData(FwdState *fwdState):
    AsyncJob("Ftp::ServerStateData"), ::ServerStateData(fwdState)
{
    ++statCounter.server.all.requests;
    ++statCounter.server.ftp.requests;

    ctrl.last_command = xstrdup("Connect to server");
    ctrl.buf = static_cast<char *>(memAllocBuf(4096, &ctrl.size));
    ctrl.offset = 0;

    typedef CommCbMemFunT<ServerStateData, CommCloseCbParams> Dialer;
    const AsyncCall::Pointer closer = JobCallback(9, 5, Dialer, this,
                                                  ServerStateData::ctrlClosed);
    ctrl.opened(fwdState->serverConnection(), closer);
}

void
ServerStateData::DataChannel::addr(const Ip::Address &import)
{
     static char addrBuf[MAX_IPSTRLEN];
     import.toStr(addrBuf, sizeof(addrBuf));
     xfree(host);
     host = xstrdup(addrBuf);
     port = import.port();
}

ServerStateData::~ServerStateData()
{
    if (data.opener != NULL) {
        data.opener->cancel("Ftp::ServerStateData destructed");
        data.opener = NULL;
    }
    data.close();

    if (ctrl.buf) {
        memFreeBuf(ctrl.size, ctrl.buf);
        ctrl.buf = NULL;
    }
    if (ctrl.message)
        wordlistDestroy(&ctrl.message);
    safe_free(ctrl.last_command);
    safe_free(ctrl.last_reply);

    if (data.readBuf) {
        if (!data.readBuf->isNull())
            data.readBuf->clean();

        delete data.readBuf;
    }

    safe_free(old_request);

    safe_free(old_reply);

    fwd = NULL; // refcounted
}

void
ServerStateData::start()
{
    scheduleReadControlReply(0);
}

void
ServerStateData::initReadBuf()
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
ServerStateData::closeServer()
{
    if (Comm::IsConnOpen(ctrl.conn)) {
        debugs(9,3, HERE << "closing FTP server FD " << ctrl.conn->fd << ", this " << this);
        fwd->unregister(ctrl.conn);
        ctrl.close();
    }

    if (Comm::IsConnOpen(data.conn)) {
        debugs(9,3, HERE << "closing FTP data FD " << data.conn->fd << ", this " << this);
        data.close();
    }

    debugs(9,3, HERE << "FTP ctrl and data connections closed. this " << this);
}

/**
 * Did we close all FTP server connection(s)?
 *
 \retval true	Both server control and data channels are closed. And not waiting for a new data connection to open.
 \retval false	Either control channel or data is still active.
 */
bool
ServerStateData::doneWithServer() const
{
    return !Comm::IsConnOpen(ctrl.conn) && !Comm::IsConnOpen(data.conn);
}

void
ServerStateData::failed(err_type error, int xerrno)
{
    debugs(9,3,HERE << "entry-null=" << (entry?entry->isEmpty():0) << ", entry=" << entry);

    const char *command, *reply;
    const Http::StatusCode httpStatus = failedHttpStatus(error);
    ErrorState *const ftperr = new ErrorState(error, httpStatus, fwd->request);
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

    fwd->fail(ftperr);

    closeServer(); // we failed, so no serverComplete()
}

Http::StatusCode
ServerStateData::failedHttpStatus(err_type &error)
{
    if (error == ERR_NONE)
        error = ERR_FTP_FAILURE;
    return error == ERR_READ_TIMEOUT ? Http::scGateway_Timeout :
        Http::scBadGateway;
}

/**
 * DPW 2007-04-23
 * Looks like there are no longer anymore callers that set
 * buffered_ok=1.  Perhaps it can be removed at some point.
 */
void
ServerStateData::scheduleReadControlReply(int buffered_ok)
{
    debugs(9, 3, HERE << ctrl.conn);

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

        typedef CommCbMemFunT<ServerStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall = JobCallback(9, 5, TimeoutDialer, this, ServerStateData::timeout);
        commSetConnTimeout(ctrl.conn, Config.Timeout.read, timeoutCall);

        typedef CommCbMemFunT<ServerStateData, CommIoCbParams> Dialer;
        AsyncCall::Pointer reader = JobCallback(9, 5, Dialer, this, ServerStateData::readControlReply);
        comm_read(ctrl.conn, ctrl.buf + ctrl.offset, ctrl.size - ctrl.offset, reader);
    }
}

void
ServerStateData::readControlReply(const CommIoCbParams &io)
{
    debugs(9, 3, HERE << "FD " << io.fd << ", Read " << io.size << " bytes");

    if (io.size > 0) {
        kb_incr(&(statCounter.server.all.kbytes_in), io.size);
        kb_incr(&(statCounter.server.ftp.kbytes_in), io.size);
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted during control reply read");
        return;
    }

    assert(ctrl.offset < ctrl.size);

    if (io.flag == COMM_OK && io.size > 0) {
        fd_bytes(io.fd, io.size, FD_READ);
    }

    if (io.flag != COMM_OK) {
        debugs(50, ignoreErrno(io.xerrno) ? 3 : DBG_IMPORTANT,
               "ftpReadControlReply: read error: " << xstrerr(io.xerrno));

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
    handleControlReply();
}

void
ServerStateData::handleControlReply()
{
    debugs(9, 3, HERE);

    size_t bytes_used = 0;
    wordlistDestroy(&ctrl.message);

    if (!parseControlReply(bytes_used)) {
        /* didn't get complete reply yet */

        if (ctrl.offset == ctrl.size) {
            ctrl.buf = (char *)memReallocBuf(ctrl.buf, ctrl.size << 1, &ctrl.size);
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

    debugs(9, 3, HERE << "state=" << state << ", code=" << ctrl.replycode);
}

bool
ServerStateData::handlePasvReply(Ip::Address &srvAddr)
{
    int code = ctrl.replycode;
    char *buf;
    debugs(9, 3, HERE);

    if (code != 227) {
        debugs(9, 2, "PASV not supported by remote end");
        return false;
    }

    /*  227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).  */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debugs(9, 5, HERE << "scanning: " << ctrl.last_reply);

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

void
ServerStateData::connectDataChannel()
{
    safe_free(ctrl.last_command);

    safe_free(ctrl.last_reply);

    ctrl.last_command = xstrdup("Connect to server data port");

    // Generate a new data channel descriptor to be opened.
    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->local = ctrl.conn->local;
    conn->local.port(0);
    conn->remote = data.host;
    conn->remote.port(data.port);

    debugs(9, 3, HERE << "connecting to " << conn->remote);

    data.opener = commCbCall(9,3, "Ftp::ServerStateData::dataChannelConnected",
                             CommConnectCbPtrFun(ServerStateData::dataChannelConnected, this));
    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, data.opener, Config.Timeout.connect);
    cs->setHost(data.host);
    AsyncJob::Start(cs);
}

void
ServerStateData::dataChannelConnected(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
{
    ServerStateData *ftpState = static_cast<ServerStateData *>(data);
    ftpState->dataChannelConnected(conn, status, xerrno);
}

/// creates a data channel Comm close callback
AsyncCall::Pointer
ServerStateData::dataCloser()
{
    typedef CommCbMemFunT<ServerStateData, CommCloseCbParams> Dialer;
    return JobCallback(9, 5, Dialer, this, ServerStateData::dataClosed);
}

/// handler called by Comm when FTP data channel is closed unexpectedly
void
ServerStateData::dataClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, HERE);
    if (data.listenConn != NULL) {
        data.listenConn->close();
        data.listenConn = NULL;
        // NP clear() does the: data.fd = -1;
    }
    data.clear();
}

void
ServerStateData::writeCommand(const char *buf)
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
        debugs(9, 2, HERE << "cannot send to closing ctrl " << ctrl.conn);
        // TODO: assert(ctrl.closer != NULL);
        return;
    }

    typedef CommCbMemFunT<ServerStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(9, 5, Dialer, this,
                                          ServerStateData::writeCommandCallback);
    Comm::Write(ctrl.conn, ctrl.last_command, strlen(ctrl.last_command), call, NULL);

    scheduleReadControlReply(0);
}

void
ServerStateData::writeCommandCallback(const CommIoCbParams &io)
{

    debugs(9, 5, HERE << "wrote " << io.size << " bytes");

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, FD_WRITE);
        kb_incr(&(statCounter.server.all.kbytes_out), io.size);
        kb_incr(&(statCounter.server.ftp.kbytes_out), io.size);
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    if (io.flag) {
        debugs(9, DBG_IMPORTANT, "ftpWriteCommandCallback: " << io.conn << ": " << xstrerr(io.xerrno));
        failed(ERR_WRITE_ERROR, io.xerrno);
        /* failed closes ctrl.conn and frees ftpState */
        return;
    }
}

/// handler called by Comm when FTP control channel is closed unexpectedly
void
ServerStateData::ctrlClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, HERE);
    ctrl.clear();
    mustStop("Ftp::ServerStateData::ctrlClosed");
}

void
ServerStateData::timeout(const CommTimeoutCbParams &io)
{
    debugs(9, 4, HERE << io.conn << ": '" << entry->url() << "'" );

    if (abortOnBadEntry("entry went bad while waiting for a timeout"))
        return;

    failed(ERR_READ_TIMEOUT, 0);
    /* failed() closes ctrl.conn and frees ftpState */
}

const Comm::ConnectionPointer &
ServerStateData::dataConnection() const
{
    return data.conn;
}

void
ServerStateData::maybeReadVirginBody()
{
    // too late to read
    if (!Comm::IsConnOpen(data.conn) || fd_table[data.conn->fd].closing())
        return;

    if (data.read_pending)
        return;

    initReadBuf();

    const int read_sz = replyBodySpace(*data.readBuf, 0);

    debugs(11,9, HERE << "FTP may read up to " << read_sz << " bytes");

    if (read_sz < 2)	// see http.cc
        return;

    data.read_pending = true;

    typedef CommCbMemFunT<ServerStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(9, 5,
                                      TimeoutDialer, this, ServerStateData::timeout);
    commSetConnTimeout(data.conn, Config.Timeout.read, timeoutCall);

    debugs(9,5,HERE << "queueing read on FD " << data.conn->fd);

    typedef CommCbMemFunT<ServerStateData, CommIoCbParams> Dialer;
    entry->delayAwareRead(data.conn, data.readBuf->space(), read_sz,
                          JobCallback(9, 5, Dialer, this, ServerStateData::dataRead));
}

void
ServerStateData::dataRead(const CommIoCbParams &io)
{
    int j;
    int bin;

    data.read_pending = false;

    debugs(9, 3, HERE << "FD " << io.fd << " Read " << io.size << " bytes");

    if (io.size > 0) {
        kb_incr(&(statCounter.server.all.kbytes_in), io.size);
        kb_incr(&(statCounter.server.ftp.kbytes_in), io.size);
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    assert(io.fd == data.conn->fd);

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted during dataRead");
        return;
    }

    if (io.flag == COMM_OK && io.size > 0) {
        debugs(9, 5, HERE << "appended " << io.size << " bytes to readBuf");
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

    if (io.flag != COMM_OK) {
        debugs(50, ignoreErrno(io.xerrno) ? 3 : DBG_IMPORTANT,
               HERE << "read error: " << xstrerr(io.xerrno));

        if (ignoreErrno(io.xerrno)) {
            typedef CommCbMemFunT<ServerStateData, CommTimeoutCbParams> TimeoutDialer;
            AsyncCall::Pointer timeoutCall =
                JobCallback(9, 5, TimeoutDialer, this,
                            ServerStateData::timeout);
            commSetConnTimeout(io.conn, Config.Timeout.read, timeoutCall);

            maybeReadVirginBody();
        } else {
            failed(ERR_READ_ERROR, 0);
            /* failed closes ctrl.conn and frees ftpState */
            return;
        }
    } else if (io.size == 0) {
        debugs(9,3, HERE << "Calling dataComplete() because io.size == 0");
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
ServerStateData::dataComplete()
{
    debugs(9, 3,HERE);

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
 *	including canceling close handlers
 */
void
ServerStateData::abortTransaction(const char *reason)
{
    debugs(9, 3, HERE << "aborting transaction for " << reason <<
           "; FD " << (ctrl.conn!=NULL?ctrl.conn->fd:-1) << ", Data FD " << (data.conn!=NULL?data.conn->fd:-1) << ", this " << this);
    if (Comm::IsConnOpen(ctrl.conn)) {
        ctrl.conn->close();
        return;
    }

    fwd->handleUnregisteredServerEnd();
    mustStop("ServerStateData::abortTransaction");
}

/**
 * Cancel the timeout on the Control socket and establish one
 * on the data socket
 */
void
ServerStateData::switchTimeoutToDataChannel()
{
    commUnsetConnTimeout(ctrl.conn);

    typedef CommCbMemFunT<ServerStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(9, 5, TimeoutDialer, this,
                                                 ServerStateData::timeout);
    commSetConnTimeout(data.conn, Config.Timeout.read, timeoutCall);
}

void
ServerStateData::sentRequestBody(const CommIoCbParams &io)
{
    if (io.size > 0)
        kb_incr(&(statCounter.server.ftp.kbytes_out), io.size);
    ::ServerStateData::sentRequestBody(io);
}

/**
 * called after we wrote the last byte of the request body
 */
void
ServerStateData::doneSendingRequestBody()
{
    ::ServerStateData::doneSendingRequestBody();
    debugs(9,3, HERE);
    dataComplete();
    /* NP: RFC 959  3.3.  DATA CONNECTION MANAGEMENT
     * if transfer type is 'stream' call dataComplete()
     * otherwise leave open. (reschedule control channel read?)
     */
}

/// Parses FTP server control response into ctrl structure fields,
/// setting bytesUsed and returning true on success.
bool
ServerStateData::parseControlReply(size_t &bytesUsed)
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
    debugs(9, 3, HERE);
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

    debugs(9, 3, HERE << "usable = " << usable);

    if (usable == 0) {
        debugs(9, 3, HERE << "didn't find end of line");
        safe_free(sbuf);
        return false;
    }

    debugs(9, 3, HERE << len << " bytes to play with");
    ++end;
    s = sbuf;
    s += strspn(s, crlf);

    for (; s < end; s += strcspn(s, crlf), s += strspn(s, crlf)) {
        if (complete)
            break;

        debugs(9, 5, HERE << "s = {" << s << "}");

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


bool
Ftp::ParseIpPort(const char *buf, const char *forceIp, Ip::Address &addr)
{
    int h1, h2, h3, h4;
    int p1, p2;
    const int n = sscanf(buf, "%d,%d,%d,%d,%d,%d",
                         &h1, &h2, &h3, &h4, &p1, &p2);

    if (n != 6 || p1 < 0 || p2 < 0 || p1 > 255 || p2 > 255)
        return false;

    if (forceIp) {
        addr = forceIp; // but the above code still validates the IP we got
    } else {
        static char ipBuf[1024];
        snprintf(ipBuf, sizeof(ipBuf), "%d.%d.%d.%d", h1, h2, h3, h4);
        addr = ipBuf;

        if (addr.isAnyAddr())
            return false;
    }

    const int port = ((p1 << 8) + p2);

    if (port <= 0)
        return false;

    if (Config.Ftp.sanitycheck && port < 1024)
        return false;

    addr.port(port);
    return true;
}
