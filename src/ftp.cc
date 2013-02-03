/*
 * DEBUG: section 09    File Transfer Protocol (FTP)
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "comm.h"
#include "comm/ConnOpener.h"
#include "comm/TcpAcceptor.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "compat/strtoll.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "forward.h"
#include "html_quote.h"
#include "HttpHdrContRange.h"
#include "HttpHeader.h"
#include "HttpHeaderRange.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ip/tools.h"
#include "Mem.h"
#include "MemBuf.h"
#include "mime.h"
#include "rfc1738.h"
#include "Server.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "tools.h"
#include "URL.h"
#include "URLScheme.h"
#include "wordlist.h"

#if USE_DELAY_POOLS
#include "DelayPools.h"
#include "MemObject.h"
#endif

#if HAVE_ERRNO_H
#include <errno.h>
#endif

/**
 \defgroup ServerProtocolFTPInternal Server-Side FTP Internals
 \ingroup ServerProtocolFTPAPI
 */

/// \ingroup ServerProtocolFTPInternal
static const char *const crlf = "\r\n";

#define CTRL_BUFLEN 1024
/// \ingroup ServerProtocolFTPInternal
static char cbuf[CTRL_BUFLEN];

/// \ingroup ServerProtocolFTPInternal
typedef enum {
    BEGIN,
    SENT_USER,
    SENT_PASS,
    SENT_TYPE,
    SENT_MDTM,
    SENT_SIZE,
    SENT_EPRT,
    SENT_PORT,
    SENT_EPSV_ALL,
    SENT_EPSV_1,
    SENT_EPSV_2,
    SENT_PASV,
    SENT_CWD,
    SENT_LIST,
    SENT_NLST,
    SENT_REST,
    SENT_RETR,
    SENT_STOR,
    SENT_QUIT,
    READING_DATA,
    WRITING_DATA,
    SENT_MKDIR
} ftp_state_t;

/// \ingroup ServerProtocolFTPInternal
struct _ftp_flags {

    /* passive mode */
    bool pasv_supported;  ///< PASV command is allowed
    bool epsv_all_sent;   ///< EPSV ALL has been used. Must abort on failures.
    bool pasv_only;
    bool pasv_failed;  // was FwdState::flags.ftp_pasv_failed

    /* authentication */
    bool authenticated;         ///< authentication success
    bool tried_auth_anonymous;  ///< auth has tried to use anonymous credentials already.
    bool tried_auth_nopass;     ///< auth tried username with no password already.

    /* other */
    bool isdir;
    bool skip_whitespace;
    bool rest_supported;
    bool http_header_sent;
    bool tried_nlst;
    bool need_base_href;
    bool dir_slash;
    bool root_dir;
    bool no_dotdot;
    bool binary;
    bool try_slash_hack;
    bool put;
    bool put_mkdir;
    bool listformat_unknown;
    bool listing;
    bool completed_forwarding;
};

class FtpStateData;

/// \ingroup ServerProtocolFTPInternal
typedef void (FTPSM) (FtpStateData *);

/// common code for FTP control and data channels
/// does not own the channel descriptor, which is managed by FtpStateData
class FtpChannel
{
public:
    FtpChannel() {};

    /// called after the socket is opened, sets up close handler
    void opened(const Comm::ConnectionPointer &conn, const AsyncCall::Pointer &aCloser);

    /** Handles all operations needed to properly close the active channel FD.
     * clearing the close handler, clearing the listen socket properly, and calling comm_close
     */
    void close();

    void clear(); ///< just drops conn and close handler. does not close active connections.

    Comm::ConnectionPointer conn; ///< channel descriptor

    /** A temporary handle to the connection being listened on.
     * Closing this will also close the waiting Data channel acceptor.
     * If a data connection has already been accepted but is still waiting in the event queue
     * the callback will still happen and needs to be handled (usually dropped).
     */
    Comm::ConnectionPointer listenConn;

    AsyncCall::Pointer opener; ///< Comm opener handler callback.
private:
    AsyncCall::Pointer closer; ///< Comm close handler callback
};

/// \ingroup ServerProtocolFTPInternal
class FtpStateData : public ServerStateData
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    void *toCbdata() { return this; }

    FtpStateData(FwdState *, const Comm::ConnectionPointer &conn);
    ~FtpStateData();
    char user[MAX_URL];
    char password[MAX_URL];
    int password_url;
    char *reply_hdr;
    int reply_hdr_state;
    String clean_url;
    String title_url;
    String base_href;
    int conn_att;
    int login_att;
    ftp_state_t state;
    time_t mdtm;
    int64_t theSize;
    wordlist *pathcomps;
    char *filepath;
    char *dirpath;
    int64_t restart_offset;
    char *proxy_host;
    size_t list_width;
    String cwd_message;
    char *old_request;
    char *old_reply;
    char *old_filepath;
    char typecode;
    MemBuf listing;		///< FTP directory listing in HTML format.

    // \todo: optimize ctrl and data structs member order, to minimize size
    /// FTP control channel info; the channel is opened once per transaction
    struct CtrlChannel: public FtpChannel {
        char *buf;
        size_t size;
        size_t offset;
        wordlist *message;
        char *last_command;
        char *last_reply;
        int replycode;
    } ctrl;

    /// FTP data channel info; the channel may be opened/closed a few times
    struct DataChannel: public FtpChannel {
        MemBuf *readBuf;
        char *host;
        unsigned short port;
        bool read_pending;
    } data;

    struct _ftp_flags flags;

private:
    CBDATA_CLASS(FtpStateData);

public:
    // these should all be private
    virtual void start();
    void loginParser(const char *, int escaped);
    int restartable();
    void appendSuccessHeader();
    void hackShortcut(FTPSM * nextState);
    void failed(err_type, int xerrno);
    void failedErrorMessage(err_type, int xerrno);
    void unhack();
    void scheduleReadControlReply(int);
    void handleControlReply();
    void readStor();
    void parseListing();
    MemBuf *htmlifyListEntry(const char *line);
    void completedListing(void);
    void dataComplete();
    void dataRead(const CommIoCbParams &io);

    /// ignore timeout on CTRL channel. set read timeout on DATA channel.
    void switchTimeoutToDataChannel();
    /// create a data channel acceptor and start listening.
    void listenForDataChannel(const Comm::ConnectionPointer &conn, const char *note);

    int checkAuth(const HttpHeader * req_hdr);
    void checkUrlpath();
    void buildTitleUrl();
    void writeReplyBody(const char *, size_t len);
    void printfReplyBody(const char *fmt, ...);
    virtual const Comm::ConnectionPointer & dataConnection() const;
    virtual void maybeReadVirginBody();
    virtual void closeServer();
    virtual void completeForwarding();
    virtual void abortTransaction(const char *reason);
    void processHeadResponse();
    void processReplyBody();
    void writeCommand(const char *buf);
    void setCurrentOffset(int64_t offset) { currentOffset = offset; }
    int64_t getCurrentOffset() const { return currentOffset; }

    static CNCB ftpPasvCallback;
    static PF ftpDataWrite;
    void ftpTimeout(const CommTimeoutCbParams &io);
    void ctrlClosed(const CommCloseCbParams &io);
    void dataClosed(const CommCloseCbParams &io);
    void ftpReadControlReply(const CommIoCbParams &io);
    void ftpWriteCommandCallback(const CommIoCbParams &io);
    void ftpAcceptDataConnection(const CommAcceptCbParams &io);

    static HttpReply *ftpAuthRequired(HttpRequest * request, const char *realm);
    const char *ftpRealm(void);
    void loginFailed(void);
    static wordlist *ftpParseControlReply(char *, size_t, int *, size_t *);

    // sending of the request body to the server
    virtual void sentRequestBody(const CommIoCbParams&);
    virtual void doneSendingRequestBody();

    virtual void haveParsedReplyHeaders();

    virtual bool doneWithServer() const;
    virtual bool haveControlChannel(const char *caller_name) const;
    AsyncCall::Pointer dataCloser(); /// creates a Comm close callback
    AsyncCall::Pointer dataOpener(); /// creates a Comm connect callback

private:
    // BodyConsumer for HTTP: consume request body.
    virtual void handleRequestBodyProducerAborted();
};

CBDATA_CLASS_INIT(FtpStateData);

void *
FtpStateData::operator new (size_t)
{
    CBDATA_INIT_TYPE(FtpStateData);
    FtpStateData *result = cbdataAlloc(FtpStateData);
    return result;
}

void
FtpStateData::operator delete (void *address)
{
    FtpStateData *t = static_cast<FtpStateData *>(address);
    cbdataFree(t);
}

/// \ingroup ServerProtocolFTPInternal
typedef struct {
    char type;
    int64_t size;
    char *date;
    char *name;
    char *showname;
    char *link;
} ftpListParts;

/// \ingroup ServerProtocolFTPInternal
#define FTP_LOGIN_ESCAPED	1

/// \ingroup ServerProtocolFTPInternal
#define FTP_LOGIN_NOT_ESCAPED	0

/*
 * State machine functions
 * send == state transition
 * read == wait for response, and select next state transition
 * other == Transition logic
 */
static FTPSM ftpReadWelcome;
static FTPSM ftpSendUser;
static FTPSM ftpReadUser;
static FTPSM ftpSendPass;
static FTPSM ftpReadPass;
static FTPSM ftpSendType;
static FTPSM ftpReadType;
static FTPSM ftpSendMdtm;
static FTPSM ftpReadMdtm;
static FTPSM ftpSendSize;
static FTPSM ftpReadSize;
static FTPSM ftpSendEPRT;
static FTPSM ftpReadEPRT;
static FTPSM ftpSendPORT;
static FTPSM ftpReadPORT;
static FTPSM ftpSendPassive;
static FTPSM ftpReadEPSV;
static FTPSM ftpReadPasv;
static FTPSM ftpTraverseDirectory;
static FTPSM ftpListDir;
static FTPSM ftpGetFile;
static FTPSM ftpSendCwd;
static FTPSM ftpReadCwd;
static FTPSM ftpRestOrList;
static FTPSM ftpSendList;
static FTPSM ftpSendNlst;
static FTPSM ftpReadList;
static FTPSM ftpSendRest;
static FTPSM ftpReadRest;
static FTPSM ftpSendRetr;
static FTPSM ftpReadRetr;
static FTPSM ftpReadTransferDone;
static FTPSM ftpSendStor;
static FTPSM ftpReadStor;
static FTPSM ftpWriteTransferDone;
static FTPSM ftpSendReply;
static FTPSM ftpSendMkdir;
static FTPSM ftpReadMkdir;
static FTPSM ftpFail;
static FTPSM ftpSendQuit;
static FTPSM ftpReadQuit;

/************************************************
** Debugs Levels used here                     **
*************************************************
0	CRITICAL Events
1	IMPORTANT Events
	Protocol and Transmission failures.
2	FTP Protocol Chatter
3	Logic Flows
4	Data Parsing Flows
5	Data Dumps
7	??
************************************************/

/************************************************
** State Machine Description (excluding hacks) **
*************************************************
From			To
---------------------------------------
Welcome			User
User			Pass
Pass			Type
Type			TraverseDirectory / GetFile
TraverseDirectory	Cwd / GetFile / ListDir
Cwd			TraverseDirectory / Mkdir
GetFile			Mdtm
Mdtm			Size
Size			Epsv
ListDir			Epsv
Epsv			FileOrList
FileOrList		Rest / Retr / Nlst / List / Mkdir (PUT /xxx;type=d)
Rest			Retr
Retr / Nlst / List	DataRead* (on datachannel)
DataRead*		ReadTransferDone
ReadTransferDone	DataTransferDone
Stor			DataWrite* (on datachannel)
DataWrite*		RequestPutBody** (from client)
RequestPutBody**	DataWrite* / WriteTransferDone
WriteTransferDone	DataTransferDone
DataTransferDone	Quit
Quit			-
************************************************/

/// \ingroup ServerProtocolFTPInternal
FTPSM *FTP_SM_FUNCS[] = {
    ftpReadWelcome,		/* BEGIN */
    ftpReadUser,		/* SENT_USER */
    ftpReadPass,		/* SENT_PASS */
    ftpReadType,		/* SENT_TYPE */
    ftpReadMdtm,		/* SENT_MDTM */
    ftpReadSize,		/* SENT_SIZE */
    ftpReadEPRT,		/* SENT_EPRT */
    ftpReadPORT,		/* SENT_PORT */
    ftpReadEPSV,		/* SENT_EPSV_ALL */
    ftpReadEPSV,		/* SENT_EPSV_1 */
    ftpReadEPSV,		/* SENT_EPSV_2 */
    ftpReadPasv,		/* SENT_PASV */
    ftpReadCwd,		/* SENT_CWD */
    ftpReadList,		/* SENT_LIST */
    ftpReadList,		/* SENT_NLST */
    ftpReadRest,		/* SENT_REST */
    ftpReadRetr,		/* SENT_RETR */
    ftpReadStor,		/* SENT_STOR */
    ftpReadQuit,		/* SENT_QUIT */
    ftpReadTransferDone,	/* READING_DATA (RETR,LIST,NLST) */
    ftpWriteTransferDone,	/* WRITING_DATA (STOR) */
    ftpReadMkdir		/* SENT_MKDIR */
};

/// handler called by Comm when FTP control channel is closed unexpectedly
void
FtpStateData::ctrlClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, HERE);
    ctrl.clear();
    mustStop("FtpStateData::ctrlClosed");
}

/// handler called by Comm when FTP data channel is closed unexpectedly
void
FtpStateData::dataClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, HERE);
    if (data.listenConn != NULL) {
        data.listenConn->close();
        data.listenConn = NULL;
        // NP clear() does the: data.fd = -1;
    }
    data.clear();
    failed(ERR_FTP_FAILURE, 0);
    /* failed closes ctrl.conn and frees ftpState */

    /* NP: failure recovery may be possible when its only a data.conn failure.
     *     if the ctrl.conn is still fine, we can send ABOR down it and retry.
     *     Just need to watch out for wider Squid states like shutting down or reconfigure.
     */
}

FtpStateData::FtpStateData(FwdState *theFwdState, const Comm::ConnectionPointer &conn) : AsyncJob("FtpStateData"), ServerStateData(theFwdState)
{
    const char *url = entry->url();
    debugs(9, 3, HERE << "'" << url << "'" );
    ++ statCounter.server.all.requests;
    ++ statCounter.server.ftp.requests;
    theSize = -1;
    mdtm = -1;

    if (Config.Ftp.passive && !flags.pasv_failed)
        flags.pasv_supported = 1;

    flags.rest_supported = 1;

    typedef CommCbMemFunT<FtpStateData, CommCloseCbParams> Dialer;
    AsyncCall::Pointer closer = JobCallback(9, 5, Dialer, this, FtpStateData::ctrlClosed);
    ctrl.opened(conn, closer);

    if (request->method == METHOD_PUT)
        flags.put = 1;
}

FtpStateData::~FtpStateData()
{
    debugs(9, 3, HERE << entry->url()  );

    if (reply_hdr) {
        memFree(reply_hdr, MEM_8K_BUF);
        reply_hdr = NULL;
    }

    if (data.opener != NULL) {
        data.opener->cancel("FtpStateData destructed");
        data.opener = NULL;
    }
    data.close();

    if (Comm::IsConnOpen(ctrl.conn)) {
        debugs(9, DBG_IMPORTANT, HERE << "Internal bug: FtpStateData left " <<
               "open control channel " << ctrl.conn);
    }

    if (ctrl.buf) {
        memFreeBuf(ctrl.size, ctrl.buf);
        ctrl.buf = NULL;
    }

    if (data.readBuf) {
        if (!data.readBuf->isNull())
            data.readBuf->clean();

        delete data.readBuf;
    }

    if (pathcomps)
        wordlistDestroy(&pathcomps);

    if (ctrl.message)
        wordlistDestroy(&ctrl.message);

    cwd_message.clean();

    safe_free(ctrl.last_reply);

    safe_free(ctrl.last_command);

    safe_free(old_request);

    safe_free(old_reply);

    safe_free(old_filepath);

    title_url.clean();

    base_href.clean();

    safe_free(filepath);

    safe_free(dirpath);

    safe_free(data.host);

    fwd = NULL;	// refcounted
}

/**
 * Parse a possible login username:password pair.
 * Produces filled member variables user, password, password_url if anything found.
 */
void
FtpStateData::loginParser(const char *login, int escaped)
{
    const char *u = NULL; // end of the username sub-string
    int len;              // length of the current sub-string to handle.

    int total_len = strlen(login);

    debugs(9, 4, HERE << ": login='" << login << "', escaped=" << escaped);
    debugs(9, 9, HERE << ": IN : login='" << login << "', escaped=" << escaped << ", user=" << user << ", password=" << password);

    if ((u = strchr(login, ':'))) {

        /* if there was a username part */
        if (u > login) {
            len = u - login;
            ++u; // jump off the delimiter.
            if (len > MAX_URL)
                len = MAX_URL-1;
            xstrncpy(user, login, len +1);
            debugs(9, 9, HERE << ": found user='" << user << "'(" << len <<"), escaped=" << escaped);
            if (escaped)
                rfc1738_unescape(user);
            debugs(9, 9, HERE << ": found user='" << user << "'(" << len <<") unescaped.");
        }

        /* if there was a password part */
        len = login + total_len - u;
        if ( len > 0) {
            if (len > MAX_URL)
                len = MAX_URL -1;
            xstrncpy(password, u, len +1);
            debugs(9, 9, HERE << ": found password='" << password << "'(" << len <<"), escaped=" << escaped);
            if (escaped) {
                rfc1738_unescape(password);
                password_url = 1;
            }
            debugs(9, 9, HERE << ": found password='" << password << "'(" << len <<") unescaped.");
        }
    } else if (login[0]) {
        /* no password, just username */
        if (total_len > MAX_URL)
            total_len = MAX_URL -1;
        xstrncpy(user, login, total_len +1);
        debugs(9, 9, HERE << ": found user='" << user << "'(" << total_len <<"), escaped=" << escaped);
        if (escaped)
            rfc1738_unescape(user);
        debugs(9, 9, HERE << ": found user='" << user << "'(" << total_len <<") unescaped.");
    }

    debugs(9, 9, HERE << ": OUT: login='" << login << "', escaped=" << escaped << ", user=" << user << ", password=" << password);
}

/**
 * Cancel the timeout on the Control socket and establish one
 * on the data socket
 */
void
FtpStateData::switchTimeoutToDataChannel()
{
    commUnsetConnTimeout(ctrl.conn);

    typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(9, 5, TimeoutDialer, this, FtpStateData::ftpTimeout);
    commSetConnTimeout(data.conn, Config.Timeout.read, timeoutCall);
}

void
FtpStateData::listenForDataChannel(const Comm::ConnectionPointer &conn, const char *note)
{
    assert(!Comm::IsConnOpen(data.conn));

    typedef CommCbMemFunT<FtpStateData, CommAcceptCbParams> AcceptDialer;
    typedef AsyncCallT<AcceptDialer> AcceptCall;
    RefCount<AcceptCall> call = static_cast<AcceptCall*>(JobCallback(11, 5, AcceptDialer, this, FtpStateData::ftpAcceptDataConnection));
    Subscription::Pointer sub = new CallSubscription<AcceptCall>(call);

    /* open the conn if its not already open */
    if (!Comm::IsConnOpen(conn)) {
        conn->fd = comm_open_listener(SOCK_STREAM, IPPROTO_TCP, conn->local, conn->flags, note);
        if (!Comm::IsConnOpen(conn)) {
            debugs(5, DBG_CRITICAL, HERE << "comm_open_listener failed:" << conn->local << " error: " << errno);
            return;
        }
        debugs(9, 3, HERE << "Unconnected data socket created on " << conn);
    }

    assert(Comm::IsConnOpen(conn));
    AsyncJob::Start(new Comm::TcpAcceptor(conn, note, sub));

    // Ensure we have a copy of the FD opened for listening and a close handler on it.
    data.opened(conn, dataCloser());
    switchTimeoutToDataChannel();
}

void
FtpStateData::ftpTimeout(const CommTimeoutCbParams &io)
{
    debugs(9, 4, HERE << io.conn << ": '" << entry->url() << "'" );

    if (abortOnBadEntry("entry went bad while waiting for a timeout"))
        return;

    if (SENT_PASV == state) {
        /* stupid ftp.netscape.com, of FTP server behind stupid firewall rules */
        flags.pasv_supported = false;
        debugs(9, DBG_IMPORTANT, "ftpTimeout: timeout in SENT_PASV state" );

        // cancel the data connection setup.
        if (data.opener != NULL) {
            data.opener->cancel("timeout");
            data.opener = NULL;
        }
        data.close();
    }

    failed(ERR_READ_TIMEOUT, 0);
    /* failed() closes ctrl.conn and frees ftpState */
}

#if DEAD_CODE // obsoleted by ERR_DIR_LISTING
void
FtpStateData::listingFinish()
{
    // TODO: figure out what this means and how to show it ...

    if (flags.listformat_unknown && !flags.tried_nlst) {
        printfReplyBody("<a href=\"%s/;type=d\">[As plain directory]</a>\n",
                        flags.dir_slash ? rfc1738_escape_part(old_filepath) : ".");
    } else if (typecode == 'D') {
        const char *path = flags.dir_slash ? filepath : ".";
        printfReplyBody("<a href=\"%s/\">[As extended directory]</a>\n", rfc1738_escape_part(path));
    }
}
#endif /* DEAD_CODE */

/// \ingroup ServerProtocolFTPInternal
static const char *Month[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/// \ingroup ServerProtocolFTPInternal
static int
is_month(const char *buf)
{
    int i;

    for (i = 0; i < 12; ++i)
        if (!strcasecmp(buf, Month[i]))
            return 1;

    return 0;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpListPartsFree(ftpListParts ** parts)
{
    safe_free((*parts)->date);
    safe_free((*parts)->name);
    safe_free((*parts)->showname);
    safe_free((*parts)->link);
    safe_free(*parts);
}

/// \ingroup ServerProtocolFTPInternal
#define MAX_TOKENS 64

/// \ingroup ServerProtocolFTPInternal
static ftpListParts *
ftpListParseParts(const char *buf, struct _ftp_flags flags)
{
    ftpListParts *p = NULL;
    char *t = NULL;
    const char *ct = NULL;
    char *tokens[MAX_TOKENS];
    int i;
    int n_tokens;
    static char tbuf[128];
    char *xbuf = NULL;
    static int scan_ftp_initialized = 0;
    static regex_t scan_ftp_integer;
    static regex_t scan_ftp_time;
    static regex_t scan_ftp_dostime;
    static regex_t scan_ftp_dosdate;

    if (!scan_ftp_initialized) {
        scan_ftp_initialized = 1;
        regcomp(&scan_ftp_integer, "^[0123456789]+$", REG_EXTENDED | REG_NOSUB);
        regcomp(&scan_ftp_time, "^[0123456789:]+$", REG_EXTENDED | REG_NOSUB);
        regcomp(&scan_ftp_dosdate, "^[0123456789]+-[0123456789]+-[0123456789]+$", REG_EXTENDED | REG_NOSUB);
        regcomp(&scan_ftp_dostime, "^[0123456789]+:[0123456789]+[AP]M$", REG_EXTENDED | REG_NOSUB | REG_ICASE);
    }

    if (buf == NULL)
        return NULL;

    if (*buf == '\0')
        return NULL;

    p = (ftpListParts *)xcalloc(1, sizeof(ftpListParts));

    n_tokens = 0;

    memset(tokens, 0, sizeof(tokens));

    xbuf = xstrdup(buf);

    if (flags.tried_nlst) {
        /* Machine readable format, one name per line */
        p->name = xbuf;
        p->type = '\0';
        return p;
    }

    for (t = strtok(xbuf, w_space); t && n_tokens < MAX_TOKENS; t = strtok(NULL, w_space)) {
        tokens[n_tokens] = xstrdup(t);
        ++n_tokens;
    }

    xfree(xbuf);

    /* locate the Month field */
    for (i = 3; i < n_tokens - 2; ++i) {
        char *size = tokens[i - 1];
        char *month = tokens[i];
        char *day = tokens[i + 1];
        char *year = tokens[i + 2];

        if (!is_month(month))
            continue;

        if (regexec(&scan_ftp_integer, size, 0, NULL, 0) != 0)
            continue;

        if (regexec(&scan_ftp_integer, day, 0, NULL, 0) != 0)
            continue;

        if (regexec(&scan_ftp_time, year, 0, NULL, 0) != 0)	/* Yr | hh:mm */
            continue;

        snprintf(tbuf, 128, "%s %2s %5s",
                 month, day, year);

        if (!strstr(buf, tbuf))
            snprintf(tbuf, 128, "%s %2s %-5s",
                     month, day, year);

        char const *copyFrom = NULL;

        if ((copyFrom = strstr(buf, tbuf))) {
            p->type = *tokens[0];
            p->size = strtoll(size, NULL, 10);
            p->date = xstrdup(tbuf);

            if (flags.skip_whitespace) {
                copyFrom += strlen(tbuf);

                while (strchr(w_space, *copyFrom))
                    ++copyFrom;
            } else {
                /* XXX assumes a single space between date and filename
                 * suggested by:  Nathan.Bailey@cc.monash.edu.au and
                 * Mike Battersby <mike@starbug.bofh.asn.au> */
                copyFrom += strlen(tbuf) + 1;
            }

            p->name = xstrdup(copyFrom);

            if (p->type == 'l' && (t = strstr(p->name, " -> "))) {
                *t = '\0';
                p->link = xstrdup(t + 4);
            }

            goto found;
        }

        break;
    }

    /* try it as a DOS listing, 04-05-70 09:33PM ... */
    if (n_tokens > 3 &&
            regexec(&scan_ftp_dosdate, tokens[0], 0, NULL, 0) == 0 &&
            regexec(&scan_ftp_dostime, tokens[1], 0, NULL, 0) == 0) {
        if (!strcasecmp(tokens[2], "<dir>")) {
            p->type = 'd';
        } else {
            p->type = '-';
            p->size = strtoll(tokens[2], NULL, 10);
        }

        snprintf(tbuf, 128, "%s %s", tokens[0], tokens[1]);
        p->date = xstrdup(tbuf);

        if (p->type == 'd') {
            /* Directory.. name begins with first printable after <dir> */
            ct = strstr(buf, tokens[2]);
            ct += strlen(tokens[2]);

            while (xisspace(*ct))
                ++ct;

            if (!*ct)
                ct = NULL;
        } else {
            /* A file. Name begins after size, with a space in between */
            snprintf(tbuf, 128, " %s %s", tokens[2], tokens[3]);
            ct = strstr(buf, tbuf);

            if (ct) {
                ct += strlen(tokens[2]) + 2;
            }
        }

        p->name = xstrdup(ct ? ct : tokens[3]);
        goto found;
    }

    /* Try EPLF format; carson@lehman.com */
    if (buf[0] == '+') {
        ct = buf + 1;
        p->type = 0;

        while (ct && *ct) {
            time_t tm;
            int l = strcspn(ct, ",");
            char *tmp;

            if (l < 1)
                goto blank;

            switch (*ct) {

            case '\t':
                p->name = xstrndup(ct + 1, l + 1);
                break;

            case 's':
                p->size = atoi(ct + 1);
                break;

            case 'm':
                tm = (time_t) strtol(ct + 1, &tmp, 0);

                if (tmp != ct + 1)
                    break;	/* not a valid integer */

                p->date = xstrdup(ctime(&tm));

                *(strstr(p->date, "\n")) = '\0';

                break;

            case '/':
                p->type = 'd';

                break;

            case 'r':
                p->type = '-';

                break;

            case 'i':
                break;

            default:
                break;
            }

blank:
            ct = strstr(ct, ",");

            if (ct) {
                ++ct;
            }
        }

        if (p->type == 0) {
            p->type = '-';
        }

        if (p->name)
            goto found;
        else
            safe_free(p->date);
    }

found:

    for (i = 0; i < n_tokens; ++i)
        xfree(tokens[i]);

    if (!p->name)
        ftpListPartsFree(&p);	/* cleanup */

    return p;
}

MemBuf *
FtpStateData::htmlifyListEntry(const char *line)
{
    char icon[2048];
    char href[2048 + 40];
    char text[ 2048];
    char size[ 2048];
    char chdir[ 2048 + 40];
    char view[ 2048 + 40];
    char download[ 2048 + 40];
    char link[ 2048 + 40];
    MemBuf *html;
    char prefix[2048];
    ftpListParts *parts;
    *icon = *href = *text = *size = *chdir = *view = *download = *link = '\0';

    debugs(9, 7, HERE << " line ={" << line << "}");

    if (strlen(line) > 1024) {
        html = new MemBuf();
        html->init();
        html->Printf("<tr><td colspan=\"5\">%s</td></tr>\n", line);
        return html;
    }

    if (flags.dir_slash && dirpath && typecode != 'D')
        snprintf(prefix, 2048, "%s/", rfc1738_escape_part(dirpath));
    else
        prefix[0] = '\0';

    if ((parts = ftpListParseParts(line, flags)) == NULL) {
        const char *p;

        html = new MemBuf();
        html->init();
        html->Printf("<tr class=\"entry\"><td colspan=\"5\">%s</td></tr>\n", line);

        for (p = line; *p && xisspace(*p); ++p);
        if (*p && !xisspace(*p))
            flags.listformat_unknown = 1;

        return html;
    }

    if (!strcmp(parts->name, ".") || !strcmp(parts->name, "..")) {
        ftpListPartsFree(&parts);
        return NULL;
    }

    parts->size += 1023;
    parts->size >>= 10;
    parts->showname = xstrdup(parts->name);

    /* {icon} {text} . . . {date}{size}{chdir}{view}{download}{link}\n  */
    xstrncpy(href, rfc1738_escape_part(parts->name), 2048);

    xstrncpy(text, parts->showname, 2048);

    switch (parts->type) {

    case 'd':
        snprintf(icon, 2048, "<img border=\"0\" src=\"%s\" alt=\"%-6s\">",
                 mimeGetIconURL("internal-dir"),
                 "[DIR]");
        strcat(href, "/");	/* margin is allocated above */
        break;

    case 'l':
        snprintf(icon, 2048, "<img border=\"0\" src=\"%s\" alt=\"%-6s\">",
                 mimeGetIconURL("internal-link"),
                 "[LINK]");
        /* sometimes there is an 'l' flag, but no "->" link */

        if (parts->link) {
            char *link2 = xstrdup(html_quote(rfc1738_escape(parts->link)));
            snprintf(link, 2048, " -&gt; <a href=\"%s%s\">%s</a>",
                     *link2 != '/' ? prefix : "", link2,
                     html_quote(parts->link));
            safe_free(link2);
        }

        break;

    case '\0':
        snprintf(icon, 2048, "<img border=\"0\" src=\"%s\" alt=\"%-6s\">",
                 mimeGetIconURL(parts->name),
                 "[UNKNOWN]");
        snprintf(chdir, 2048, "<a href=\"%s/;type=d\"><img border=\"0\" src=\"%s\" "
                 "alt=\"[DIR]\"></a>",
                 rfc1738_escape_part(parts->name),
                 mimeGetIconURL("internal-dir"));
        break;

    case '-':

    default:
        snprintf(icon, 2048, "<img border=\"0\" src=\"%s\" alt=\"%-6s\">",
                 mimeGetIconURL(parts->name),
                 "[FILE]");
        snprintf(size, 2048, " %6" PRId64 "k", parts->size);
        break;
    }

    if (parts->type != 'd') {
        if (mimeGetViewOption(parts->name)) {
            snprintf(view, 2048, "<a href=\"%s%s;type=a\"><img border=\"0\" src=\"%s\" "
                     "alt=\"[VIEW]\"></a>",
                     prefix, href, mimeGetIconURL("internal-view"));
        }

        if (mimeGetDownloadOption(parts->name)) {
            snprintf(download, 2048, "<a href=\"%s%s;type=i\"><img border=\"0\" src=\"%s\" "
                     "alt=\"[DOWNLOAD]\"></a>",
                     prefix, href, mimeGetIconURL("internal-download"));
        }
    }

    /* construct the table row from parts. */
    html = new MemBuf();
    html->init();
    html->Printf("<tr class=\"entry\">"
                 "<td class=\"icon\"><a href=\"%s%s\">%s</a></td>"
                 "<td class=\"filename\"><a href=\"%s%s\">%s</a></td>"
                 "<td class=\"date\">%s</td>"
                 "<td class=\"size\">%s</td>"
                 "<td class=\"actions\">%s%s%s%s</td>"
                 "</tr>\n",
                 prefix, href, icon,
                 prefix, href, html_quote(text),
                 parts->date,
                 size,
                 chdir, view, download, link);

    ftpListPartsFree(&parts);
    return html;
}

void
FtpStateData::parseListing()
{
    char *buf = data.readBuf->content();
    char *sbuf;			/* NULL-terminated copy of termedBuf */
    char *end;
    char *line;
    char *s;
    MemBuf *t;
    size_t linelen;
    size_t usable;
    size_t len = data.readBuf->contentSize();

    if (!len) {
        debugs(9, 3, HERE << "no content to parse for " << entry->url()  );
        return;
    }

    /*
     * We need a NULL-terminated buffer for scanning, ick
     */
    sbuf = (char *)xmalloc(len + 1);
    xstrncpy(sbuf, buf, len + 1);
    end = sbuf + len - 1;

    while (*end != '\r' && *end != '\n' && end > sbuf)
        --end;

    usable = end - sbuf;

    debugs(9, 3, HERE << "usable = " << usable << " of " << len << " bytes.");

    if (usable == 0) {
        if (buf[0] == '\0' && len == 1) {
            debugs(9, 3, HERE << "NIL ends data from " << entry->url() << " transfer problem?");
            data.readBuf->consume(len);
        } else {
            debugs(9, 3, HERE << "didn't find end for " << entry->url());
            debugs(9, 3, HERE << "buffer remains (" << len << " bytes) '" << rfc1738_do_escape(buf,0) << "'");
        }
        xfree(sbuf);
        return;
    }

    debugs(9, 3, HERE << (unsigned long int)len << " bytes to play with");

    line = (char *)memAllocate(MEM_4K_BUF);
    ++end;
    s = sbuf;
    s += strspn(s, crlf);

    for (; s < end; s += strcspn(s, crlf), s += strspn(s, crlf)) {
        debugs(9, 7, HERE << "s = {" << s << "}");
        linelen = strcspn(s, crlf) + 1;

        if (linelen < 2)
            break;

        if (linelen > 4096)
            linelen = 4096;

        xstrncpy(line, s, linelen);

        debugs(9, 7, HERE << "{" << line << "}");

        if (!strncmp(line, "total", 5))
            continue;

        t = htmlifyListEntry(line);

        if ( t != NULL) {
            debugs(9, 7, HERE << "listing append: t = {" << t->contentSize() << ", '" << t->content() << "'}");
            listing.append(t->content(), t->contentSize());
//leak?            delete t;
        }
    }

    debugs(9, 7, HERE << "Done.");
    data.readBuf->consume(usable);
    memFree(line, MEM_4K_BUF);
    xfree(sbuf);
}

const Comm::ConnectionPointer &
FtpStateData::dataConnection() const
{
    return data.conn;
}

void
FtpStateData::dataComplete()
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

void
FtpStateData::maybeReadVirginBody()
{
    // too late to read
    if (!Comm::IsConnOpen(data.conn) || fd_table[data.conn->fd].closing())
        return;

    if (data.read_pending)
        return;

    const int read_sz = replyBodySpace(*data.readBuf, 0);

    debugs(11,9, HERE << "FTP may read up to " << read_sz << " bytes");

    if (read_sz < 2)	// see http.cc
        return;

    data.read_pending = true;

    typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(9, 5,
                                      TimeoutDialer, this, FtpStateData::ftpTimeout);
    commSetConnTimeout(data.conn, Config.Timeout.read, timeoutCall);

    debugs(9,5,HERE << "queueing read on FD " << data.conn->fd);

    typedef CommCbMemFunT<FtpStateData, CommIoCbParams> Dialer;
    entry->delayAwareRead(data.conn, data.readBuf->space(), read_sz,
                          JobCallback(9, 5, Dialer, this, FtpStateData::dataRead));
}

void
FtpStateData::dataRead(const CommIoCbParams &io)
{
    int j;
    int bin;

    data.read_pending = false;

    debugs(9, 3, HERE << "ftpDataRead: FD " << io.fd << " Read " << io.size << " bytes");

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
        debugs(9,5,HERE << "appended " << io.size << " bytes to readBuf");
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
               "ftpDataRead: read error: " << xstrerr(io.xerrno));

        if (ignoreErrno(io.xerrno)) {
            typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
            AsyncCall::Pointer timeoutCall = JobCallback(9, 5,
                                             TimeoutDialer, this, FtpStateData::ftpTimeout);
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
FtpStateData::processReplyBody()
{
    debugs(9, 3, HERE << "FtpStateData::processReplyBody starting.");

    if (request->method == METHOD_HEAD && (flags.isdir || theSize != -1)) {
        serverComplete();
        return;
    }

    /* Directory listings are special. They write ther own headers via the error objects */
    if (!flags.http_header_sent && data.readBuf->contentSize() >= 0 && !flags.isdir)
        appendSuccessHeader();

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
        debugs(9,3, HERE << "returning from FtpStateData::processReplyBody due to adaptationAccessCheckPending");
        return;
    }

#endif

    if (flags.isdir) {
        if (!flags.listing) {
            flags.listing = 1;
            listing.reset();
        }
        parseListing();
        maybeReadVirginBody();
        return;
    } else if (const int csize = data.readBuf->contentSize()) {
        writeReplyBody(data.readBuf->content(), csize);
        debugs(9, 5, HERE << "consuming " << csize << " bytes of readBuf");
        data.readBuf->consume(csize);
    }

    entry->flush();

    maybeReadVirginBody();
}

/**
 * Locates the FTP user:password login.
 *
 * Highest to lowest priority:
 *  - Checks URL (ftp://user:pass@domain)
 *  - Authorization: Basic header
 *  - squid.conf anonymous-FTP settings (default: anonymous:Squid@).
 *
 * Special Case: A username-only may be provided in the URL and password in the HTTP headers.
 *
 * TODO: we might be able to do something about locating username from other sources:
 *       ie, external ACL user=* tag or ident lookup
 *
 \retval 1	if we have everything needed to complete this request.
 \retval 0	if something is missing.
 */
int
FtpStateData::checkAuth(const HttpHeader * req_hdr)
{
    /* default username */
    xstrncpy(user, "anonymous", MAX_URL);

#if HAVE_AUTH_MODULE_BASIC
    /* Check HTTP Authorization: headers (better than defaults, but less than URL) */
    const char *auth;
    if ( (auth = req_hdr->getAuth(HDR_AUTHORIZATION, "Basic")) ) {
        flags.authenticated = 1;
        loginParser(auth, FTP_LOGIN_NOT_ESCAPED);
    }
    /* we fail with authorization-required error later IFF the FTP server requests it */
#endif

    /* Test URL login syntax. Overrides any headers received. */
    loginParser(request->login, FTP_LOGIN_ESCAPED);

    /* name is missing. thats fatal. */
    if (!user[0])
        fatal("FTP login parsing destroyed username info");

    /* name + password == success */
    if (password[0])
        return 1;

    /* Setup default FTP password settings */
    /* this has to be done last so that we can have a no-password case above. */
    if (!password[0]) {
        if (strcmp(user, "anonymous") == 0 && !flags.tried_auth_anonymous) {
            xstrncpy(password, Config.Ftp.anon_user, MAX_URL);
            flags.tried_auth_anonymous=1;
            return 1;
        } else if (!flags.tried_auth_nopass) {
            xstrncpy(password, null_string, MAX_URL);
            flags.tried_auth_nopass=1;
            return 1;
        }
    }

    return 0;			/* different username */
}

static String str_type_eq;
void
FtpStateData::checkUrlpath()
{
    int l;
    size_t t;

    if (str_type_eq.undefined()) //hack. String doesn't support global-static
        str_type_eq="type=";

    if ((t = request->urlpath.rfind(';')) != String::npos) {
        if (request->urlpath.substr(t+1,t+1+str_type_eq.size())==str_type_eq) {
            typecode = (char)xtoupper(request->urlpath[t+str_type_eq.size()+1]);
            request->urlpath.cut(t);
        }
    }

    l = request->urlpath.size();
    /* check for null path */

    if (!l) {
        flags.isdir = 1;
        flags.root_dir = 1;
        flags.need_base_href = 1;	/* Work around broken browsers */
    } else if (!request->urlpath.cmp("/%2f/")) {
        /* UNIX root directory */
        flags.isdir = 1;
        flags.root_dir = 1;
    } else if ((l >= 1) && (request->urlpath[l - 1] == '/')) {
        /* Directory URL, ending in / */
        flags.isdir = 1;

        if (l == 1)
            flags.root_dir = 1;
    } else {
        flags.dir_slash = 1;
    }
}

void
FtpStateData::buildTitleUrl()
{
    title_url = "ftp://";

    if (strcmp(user, "anonymous")) {
        title_url.append(user);
        title_url.append("@");
    }

    title_url.append(request->GetHost());

    if (request->port != urlDefaultPort(AnyP::PROTO_FTP)) {
        title_url.append(":");
        title_url.append(xitoa(request->port));
    }

    title_url.append (request->urlpath);

    base_href = "ftp://";

    if (strcmp(user, "anonymous") != 0) {
        base_href.append(rfc1738_escape_part(user));

        if (password_url) {
            base_href.append (":");
            base_href.append(rfc1738_escape_part(password));
        }

        base_href.append("@");
    }

    base_href.append(request->GetHost());

    if (request->port != urlDefaultPort(AnyP::PROTO_FTP)) {
        base_href.append(":");
        base_href.append(xitoa(request->port));
    }

    base_href.append(request->urlpath);
    base_href.append("/");
}

/// \ingroup ServerProtocolFTPAPI
void
ftpStart(FwdState * fwd)
{
    AsyncJob::Start(new FtpStateData(fwd, fwd->serverConnection()));
}

void
FtpStateData::start()
{
    if (!checkAuth(&request->header)) {
        /* create appropriate reply */
        HttpReply *reply = ftpAuthRequired(request, ftpRealm());
        entry->replaceHttpReply(reply);
        serverComplete();
        return;
    }

    checkUrlpath();
    buildTitleUrl();
    debugs(9, 5, HERE << "FD " << ctrl.conn->fd << " : host=" << request->GetHost() <<
           ", path=" << request->urlpath << ", user=" << user << ", passwd=" << password);

    state = BEGIN;
    ctrl.last_command = xstrdup("Connect to server");
    ctrl.buf = (char *)memAllocBuf(4096, &ctrl.size);
    ctrl.offset = 0;
    data.readBuf = new MemBuf;
    data.readBuf->init(4096, SQUID_TCP_SO_RCVBUF);
    scheduleReadControlReply(0);
}

/* ====================================================================== */

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

void
FtpStateData::writeCommand(const char *buf)
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

    typedef CommCbMemFunT<FtpStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(9, 5, Dialer, this, FtpStateData::ftpWriteCommandCallback);
    Comm::Write(ctrl.conn, ctrl.last_command, strlen(ctrl.last_command), call, NULL);

    scheduleReadControlReply(0);
}

void
FtpStateData::ftpWriteCommandCallback(const CommIoCbParams &io)
{

    debugs(9, 5, "ftpWriteCommandCallback: wrote " << io.size << " bytes");

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

wordlist *
FtpStateData::ftpParseControlReply(char *buf, size_t len, int *codep, size_t *used)
{
    char *s;
    char *sbuf;
    char *end;
    int usable;
    int complete = 0;
    wordlist *head = NULL;
    wordlist *list;
    wordlist **tail = &head;
    size_t offset;
    size_t linelen;
    int code = -1;
    debugs(9, 3, HERE);
    /*
     * We need a NULL-terminated buffer for scanning, ick
     */
    sbuf = (char *)xmalloc(len + 1);
    xstrncpy(sbuf, buf, len + 1);
    end = sbuf + len - 1;

    while (*end != '\r' && *end != '\n' && end > sbuf)
        --end;

    usable = end - sbuf;

    debugs(9, 3, HERE << "usable = " << usable);

    if (usable == 0) {
        debugs(9, 3, HERE << "didn't find end of line");
        safe_free(sbuf);
        return NULL;
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

        if (complete)
            code = atoi(s);

        offset = 0;

        if (linelen > 3)
            if (*s >= '0' && *s <= '9' && (*(s + 3) == '-' || *(s + 3) == ' '))
                offset = 4;

        list = new wordlist();

        list->key = (char *)xmalloc(linelen - offset);

        xstrncpy(list->key, s + offset, linelen - offset);

        /* trace the FTP communication chat at level 2 */
        debugs(9, 2, "ftp>> " << code << " " << list->key);

        *tail = list;

        tail = &list->next;
    }

    *used = (size_t) (s - sbuf);
    safe_free(sbuf);

    if (!complete)
        wordlistDestroy(&head);

    if (codep)
        *codep = code;

    return head;
}

/**
 * DPW 2007-04-23
 * Looks like there are no longer anymore callers that set
 * buffered_ok=1.  Perhaps it can be removed at some point.
 */
void
FtpStateData::scheduleReadControlReply(int buffered_ok)
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

        typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall = JobCallback(9, 5, TimeoutDialer, this, FtpStateData::ftpTimeout);
        commSetConnTimeout(ctrl.conn, Config.Timeout.read, timeoutCall);

        typedef CommCbMemFunT<FtpStateData, CommIoCbParams> Dialer;
        AsyncCall::Pointer reader = JobCallback(9, 5, Dialer, this, FtpStateData::ftpReadControlReply);
        comm_read(ctrl.conn, ctrl.buf + ctrl.offset, ctrl.size - ctrl.offset, reader);
    }
}

void FtpStateData::ftpReadControlReply(const CommIoCbParams &io)
{
    debugs(9, 3, "ftpReadControlReply: FD " << io.fd << ", Read " << io.size << " bytes");

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
FtpStateData::handleControlReply()
{
    wordlist **W;
    size_t bytes_used = 0;
    wordlistDestroy(&ctrl.message);
    ctrl.message = ftpParseControlReply(ctrl.buf,
                                        ctrl.offset, &ctrl.replycode, &bytes_used);

    if (ctrl.message == NULL) {
        /* didn't get complete reply yet */

        if (ctrl.offset == ctrl.size) {
            ctrl.buf = (char *)memReallocBuf(ctrl.buf, ctrl.size << 1, &ctrl.size);
        }

        scheduleReadControlReply(0);
        return;
    } else if (ctrl.offset == bytes_used) {
        /* used it all up */
        ctrl.offset = 0;
    } else {
        /* Got some data past the complete reply */
        assert(bytes_used < ctrl.offset);
        ctrl.offset -= bytes_used;
        memmove(ctrl.buf, ctrl.buf + bytes_used, ctrl.offset);
    }

    /* Move the last line of the reply message to ctrl.last_reply */
    for (W = &ctrl.message; (*W)->next; W = &(*W)->next);
    safe_free(ctrl.last_reply);

    ctrl.last_reply = xstrdup((*W)->key);

    wordlistDestroy(W);

    /* Copy the rest of the message to cwd_message to be printed in
     * error messages
     */
    if (ctrl.message) {
        for (wordlist *w = ctrl.message; w; w = w->next) {
            cwd_message.append('\n');
            cwd_message.append(w->key);
        }
    }

    debugs(9, 3, HERE << "state=" << state << ", code=" << ctrl.replycode);

    FTP_SM_FUNCS[state] (this);
}

/* ====================================================================== */

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadWelcome(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (ftpState->flags.pasv_only)
        ++ ftpState->login_att;

    if (code == 220) {
        if (ftpState->ctrl.message) {
            if (strstr(ftpState->ctrl.message->key, "NetWare"))
                ftpState->flags.skip_whitespace = 1;
        }

        ftpSendUser(ftpState);
    } else if (code == 120) {
        if (NULL != ftpState->ctrl.message)
            debugs(9, DBG_IMPORTANT, "FTP server is busy: " << ftpState->ctrl.message->key);

        return;
    } else {
        ftpFail(ftpState);
    }
}

/**
 * Translate FTP login failure into HTTP error
 * this is an attmpt to get the 407 message to show up outside Squid.
 * its NOT a general failure. But a correct FTP response type.
 */
void
FtpStateData::loginFailed()
{
    ErrorState *err = NULL;
    const char *command, *reply;

    if ((state == SENT_USER || state == SENT_PASS) && ctrl.replycode >= 400) {
        if (ctrl.replycode == 421 || ctrl.replycode == 426) {
            // 421/426 - Service Overload - retry permitted.
            err = new ErrorState(ERR_FTP_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE, fwd->request);
        } else if (ctrl.replycode >= 430 && ctrl.replycode <= 439) {
            // 43x - Invalid or Credential Error - retry challenge required.
            err = new ErrorState(ERR_FTP_FORBIDDEN, HTTP_UNAUTHORIZED, fwd->request);
        } else if (ctrl.replycode >= 530 && ctrl.replycode <= 539) {
            // 53x - Credentials Missing - retry challenge required
            if (password_url) // but they were in the URI! major fail.
                err = new ErrorState(ERR_FTP_FORBIDDEN, HTTP_FORBIDDEN, fwd->request);
            else
                err = new ErrorState(ERR_FTP_FORBIDDEN, HTTP_UNAUTHORIZED, fwd->request);
        }
    }

    // any other problems are general falures.
    if (!err) {
        ftpFail(this);
        return;
    }

    err->ftp.server_msg = ctrl.message;

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
        err->ftp.request = xstrdup(command);

    if (reply)
        err->ftp.reply = xstrdup(reply);

    HttpReply *newrep = err->BuildHttpReply();
    delete err;

#if HAVE_AUTH_MODULE_BASIC
    /* add Authenticate header */
    newrep->header.putAuth("Basic", ftpRealm());
#endif

    // add it to the store entry for response....
    entry->replaceHttpReply(newrep);
    serverComplete();
}

const char *
FtpStateData::ftpRealm()
{
    static char realm[8192];

    /* This request is not fully authenticated */
    if (!request) {
        snprintf(realm, 8192, "FTP %s unknown", user);
    } else if (request->port == 21) {
        snprintf(realm, 8192, "FTP %s %s", user, request->GetHost());
    } else {
        snprintf(realm, 8192, "FTP %s %s port %d", user, request->GetHost(), request->port);
    }
    return realm;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendUser(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendUser"))
        return;

    if (ftpState->proxy_host != NULL)
        snprintf(cbuf, CTRL_BUFLEN, "USER %s@%s\r\n",
                 ftpState->user,
                 ftpState->request->GetHost());
    else
        snprintf(cbuf, CTRL_BUFLEN, "USER %s\r\n", ftpState->user);

    ftpState->writeCommand(cbuf);

    ftpState->state = SENT_USER;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadUser(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 230) {
        ftpReadPass(ftpState);
    } else if (code == 331) {
        ftpSendPass(ftpState);
    } else {
        ftpState->loginFailed();
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendPass(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendPass"))
        return;

    snprintf(cbuf, CTRL_BUFLEN, "PASS %s\r\n", ftpState->password);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_PASS;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadPass(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE << "code=" << code);

    if (code == 230) {
        ftpSendType(ftpState);
    } else {
        ftpState->loginFailed();
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendType(FtpStateData * ftpState)
{
    const char *t;
    const char *filename;
    char mode;

    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendType"))
        return;

    /*
     * Ref section 3.2.2 of RFC 1738
     */
    mode = ftpState->typecode;

    switch (mode) {

    case 'D':
        mode = 'A';
        break;

    case 'A':

    case 'I':
        break;

    default:

        if (ftpState->flags.isdir) {
            mode = 'A';
        } else {
            t = ftpState->request->urlpath.rpos('/');
            filename = t ? t + 1 : ftpState->request->urlpath.termedBuf();
            mode = mimeGetTransferMode(filename);
        }

        break;
    }

    if (mode == 'I')
        ftpState->flags.binary = 1;
    else
        ftpState->flags.binary = 0;

    snprintf(cbuf, CTRL_BUFLEN, "TYPE %c\r\n", mode);

    ftpState->writeCommand(cbuf);

    ftpState->state = SENT_TYPE;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadType(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    char *path;
    char *d, *p;
    debugs(9, 3, HERE << "code=" << code);

    if (code == 200) {
        p = path = xstrdup(ftpState->request->urlpath.termedBuf());

        if (*p == '/')
            ++p;

        while (*p) {
            d = p;
            p += strcspn(p, "/");

            if (*p) {
                *p = '\0';
                ++p;
            }

            rfc1738_unescape(d);

            if (*d)
                wordlistAdd(&ftpState->pathcomps, d);
        }

        xfree(path);

        if (ftpState->pathcomps)
            ftpTraverseDirectory(ftpState);
        else
            ftpListDir(ftpState);
    } else {
        ftpFail(ftpState);
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpTraverseDirectory(FtpStateData * ftpState)
{
    wordlist *w;
    debugs(9, 4, HERE << (ftpState->filepath ? ftpState->filepath : "<NULL>"));

    safe_free(ftpState->dirpath);
    ftpState->dirpath = ftpState->filepath;
    ftpState->filepath = NULL;

    /* Done? */

    if (ftpState->pathcomps == NULL) {
        debugs(9, 3, HERE << "the final component was a directory");
        ftpListDir(ftpState);
        return;
    }

    /* Go to next path component */
    w = ftpState->pathcomps;

    ftpState->filepath = w->key;

    ftpState->pathcomps = w->next;

    delete w;

    /* Check if we are to CWD or RETR */
    if (ftpState->pathcomps != NULL || ftpState->flags.isdir) {
        ftpSendCwd(ftpState);
    } else {
        debugs(9, 3, HERE << "final component is probably a file");
        ftpGetFile(ftpState);
        return;
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendCwd(FtpStateData * ftpState)
{
    char *path = NULL;

    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendCwd"))
        return;

    debugs(9, 3, HERE);

    path = ftpState->filepath;

    if (!strcmp(path, "..") || !strcmp(path, "/")) {
        ftpState->flags.no_dotdot = 1;
    } else {
        ftpState->flags.no_dotdot = 0;
    }

    snprintf(cbuf, CTRL_BUFLEN, "CWD %s\r\n", path);

    ftpState->writeCommand(cbuf);

    ftpState->state = SENT_CWD;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadCwd(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code >= 200 && code < 300) {
        /* CWD OK */
        ftpState->unhack();

        /* Reset cwd_message to only include the last message */
        ftpState->cwd_message.reset("");
        for (wordlist *w = ftpState->ctrl.message; w; w = w->next) {
            ftpState->cwd_message.append(' ');
            ftpState->cwd_message.append(w->key);
        }
        ftpState->ctrl.message = NULL;

        /* Continue to traverse the path */
        ftpTraverseDirectory(ftpState);
    } else {
        /* CWD FAILED */

        if (!ftpState->flags.put)
            ftpFail(ftpState);
        else
            ftpSendMkdir(ftpState);
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendMkdir(FtpStateData * ftpState)
{
    char *path = NULL;

    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendMkdir"))
        return;

    path = ftpState->filepath;
    debugs(9, 3, HERE << "with path=" << path);
    snprintf(cbuf, CTRL_BUFLEN, "MKD %s\r\n", path);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_MKDIR;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadMkdir(FtpStateData * ftpState)
{
    char *path = ftpState->filepath;
    int code = ftpState->ctrl.replycode;

    debugs(9, 3, HERE << "path " << path << ", code " << code);

    if (code == 257) {		/* success */
        ftpSendCwd(ftpState);
    } else if (code == 550) {	/* dir exists */

        if (ftpState->flags.put_mkdir) {
            ftpState->flags.put_mkdir = 1;
            ftpSendCwd(ftpState);
        } else
            ftpSendReply(ftpState);
    } else
        ftpSendReply(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpGetFile(FtpStateData * ftpState)
{
    assert(*ftpState->filepath != '\0');
    ftpState->flags.isdir = 0;
    ftpSendMdtm(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpListDir(FtpStateData * ftpState)
{
    if (ftpState->flags.dir_slash) {
        debugs(9, 3, HERE << "Directory path did not end in /");
        ftpState->title_url.append("/");
        ftpState->flags.isdir = 1;
    }

    ftpSendPassive(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendMdtm(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendMdtm"))
        return;

    assert(*ftpState->filepath != '\0');
    snprintf(cbuf, CTRL_BUFLEN, "MDTM %s\r\n", ftpState->filepath);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_MDTM;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadMdtm(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 213) {
        ftpState->mdtm = parse_iso3307_time(ftpState->ctrl.last_reply);
        ftpState->unhack();
    } else if (code < 0) {
        ftpFail(ftpState);
        return;
    }

    ftpSendSize(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendSize(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendSize"))
        return;

    /* Only send SIZE for binary transfers. The returned size
     * is useless on ASCII transfers */

    if (ftpState->flags.binary) {
        assert(ftpState->filepath != NULL);
        assert(*ftpState->filepath != '\0');
        snprintf(cbuf, CTRL_BUFLEN, "SIZE %s\r\n", ftpState->filepath);
        ftpState->writeCommand(cbuf);
        ftpState->state = SENT_SIZE;
    } else
        /* Skip to next state no non-binary transfers */
        ftpSendPassive(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadSize(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 213) {
        ftpState->unhack();
        ftpState->theSize = strtoll(ftpState->ctrl.last_reply, NULL, 10);

        if (ftpState->theSize == 0) {
            debugs(9, 2, "SIZE reported " <<
                   ftpState->ctrl.last_reply << " on " <<
                   ftpState->title_url);
            ftpState->theSize = -1;
        }
    } else if (code < 0) {
        ftpFail(ftpState);
        return;
    }

    ftpSendPassive(ftpState);
}

/**
 \ingroup ServerProtocolFTPInternal
 */
static void
ftpReadEPSV(FtpStateData* ftpState)
{
    int code = ftpState->ctrl.replycode;
    Ip::Address ipa_remote;
    char *buf;
    debugs(9, 3, HERE);

    if (code != 229 && code != 522) {
        if (code == 200) {
            /* handle broken servers (RFC 2428 says OK code for EPSV MUST be 229 not 200) */
            /* vsftpd for one send '200 EPSV ALL ok.' without even port info.
             * Its okay to re-send EPSV 1/2 but nothing else. */
            debugs(9, DBG_IMPORTANT, "Broken FTP Server at " << ftpState->ctrl.conn->remote << ". Wrong accept code for EPSV");
        } else {
            debugs(9, 2, "EPSV not supported by remote end");
            ftpState->state = SENT_EPSV_1; /* simulate having failed EPSV 1 (last EPSV to try before shifting to PASV) */
        }
        ftpSendPassive(ftpState);
        return;
    }

    if (code == 522) {
        /* server response with list of supported methods   */
        /*   522 Network protocol not supported, use (1)    */
        /*   522 Network protocol not supported, use (1,2)  */
        /*   522 Network protocol not supported, use (2)  */
        /* TODO: handle the (1,2) case. We might get it back after EPSV ALL
         * which means close data + control without self-destructing and re-open from scratch. */
        debugs(9, 5, HERE << "scanning: " << ftpState->ctrl.last_reply);
        buf = ftpState->ctrl.last_reply;
        while (buf != NULL && *buf != '\0' && *buf != '\n' && *buf != '(')
            ++buf;
        if (buf != NULL && *buf == '\n')
            ++buf;

        if (buf == NULL || *buf == '\0') {
            /* handle broken server (RFC 2428 says MUST specify supported protocols in 522) */
            debugs(9, DBG_IMPORTANT, "Broken FTP Server at " << ftpState->ctrl.conn->remote << ". 522 error missing protocol negotiation hints");
            ftpSendPassive(ftpState);
        } else if (strcmp(buf, "(1)") == 0) {
            ftpState->state = SENT_EPSV_2; /* simulate having sent and failed EPSV 2 */
            ftpSendPassive(ftpState);
        } else if (strcmp(buf, "(2)") == 0) {
            if (Ip::EnableIpv6) {
                /* If server only supports EPSV 2 and we have already tried that. Go straight to EPRT */
                if (ftpState->state == SENT_EPSV_2) {
                    ftpSendEPRT(ftpState);
                } else {
                    /* or try the next Passive mode down the chain. */
                    ftpSendPassive(ftpState);
                }
            } else {
                /* Server only accept EPSV in IPv6 traffic. */
                ftpState->state = SENT_EPSV_1; /* simulate having sent and failed EPSV 1 */
                ftpSendPassive(ftpState);
            }
        } else {
            /* handle broken server (RFC 2428 says MUST specify supported protocols in 522) */
            debugs(9, DBG_IMPORTANT, "WARNING: Server at " << ftpState->ctrl.conn->remote << " sent unknown protocol negotiation hint: " << buf);
            ftpSendPassive(ftpState);
        }
        return;
    }

    /*  229 Entering Extended Passive Mode (|||port|) */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debugs(9, 5, "scanning: " << ftpState->ctrl.last_reply);

    buf = ftpState->ctrl.last_reply + strcspn(ftpState->ctrl.last_reply, "(");

    char h1, h2, h3, h4;
    unsigned short port;
    int n = sscanf(buf, "(%c%c%c%hu%c)", &h1, &h2, &h3, &port, &h4);

    if (n < 4 || h1 != h2 || h1 != h3 || h1 != h4) {
        debugs(9, DBG_IMPORTANT, "Invalid EPSV reply from " <<
               ftpState->ctrl.conn->remote << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendPassive(ftpState);
        return;
    }

    if (0 == port) {
        debugs(9, DBG_IMPORTANT, "Unsafe EPSV reply from " <<
               ftpState->ctrl.conn->remote << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendPassive(ftpState);
        return;
    }

    if (Config.Ftp.sanitycheck) {
        if (port < 1024) {
            debugs(9, DBG_IMPORTANT, "Unsafe EPSV reply from " <<
                   ftpState->ctrl.conn->remote << ": " <<
                   ftpState->ctrl.last_reply);

            ftpSendPassive(ftpState);
            return;
        }
    }

    ftpState->data.port = port;

    safe_free(ftpState->data.host);
    ftpState->data.host = xstrdup(fd_table[ftpState->ctrl.conn->fd].ipaddr);

    safe_free(ftpState->ctrl.last_command);

    safe_free(ftpState->ctrl.last_reply);

    ftpState->ctrl.last_command = xstrdup("Connect to server data port");

    // Generate a new data channel descriptor to be opened.
    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->local = ftpState->ctrl.conn->local;
    conn->local.SetPort(0);
    conn->remote = ftpState->ctrl.conn->remote;
    conn->remote.SetPort(port);

    debugs(9, 3, HERE << "connecting to " << conn->remote);

    ftpState->data.opener = commCbCall(9,3, "FtpStateData::ftpPasvCallback", CommConnectCbPtrFun(FtpStateData::ftpPasvCallback, ftpState));
    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, ftpState->data.opener, Config.Timeout.connect);
    cs->setHost(ftpState->data.host);
    AsyncJob::Start(cs);
}

/** \ingroup ServerProtocolFTPInternal
 *
 * Send Passive connection request.
 * Default method is to use modern EPSV request.
 * The failover mechanism should check for previous state and re-call with alternates on failure.
 */
static void
ftpSendPassive(FtpStateData * ftpState)
{
    /** Checks the server control channel is still available before running. */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendPassive"))
        return;

    debugs(9, 3, HERE);

    /** \par
      * Checks for EPSV ALL special conditions:
      * If enabled to be sent, squid MUST NOT request any other connect methods.
      * If 'ALL' is sent and fails the entire FTP Session fails.
      * NP: By my reading exact EPSV protocols maybe attempted, but only EPSV method. */
    if (Config.Ftp.epsv_all && ftpState->flags.epsv_all_sent && ftpState->state == SENT_EPSV_1 ) {
        debugs(9, DBG_IMPORTANT, "FTP does not allow PASV method after 'EPSV ALL' has been sent.");
        ftpFail(ftpState);
        return;
    }

    /** \par
      * Checks for 'HEAD' method request and passes off for special handling by FtpStateData::processHeadResponse(). */
    if (ftpState->request->method == METHOD_HEAD && (ftpState->flags.isdir || ftpState->theSize != -1)) {
        ftpState->processHeadResponse(); // may call serverComplete
        return;
    }

    /// Closes any old FTP-Data connection which may exist. */
    ftpState->data.close();

    /** \par
      * Checks for previous EPSV/PASV failures on this server/session.
      * Diverts to EPRT immediately if they are not working. */
    if (!ftpState->flags.pasv_supported) {
        ftpSendEPRT(ftpState);
        return;
    }

    /** \par
      * Send EPSV (ALL,2,1) or PASV on the control channel.
      *
      *  - EPSV ALL  is used if enabled.
      *  - EPSV 2    is used if ALL is disabled and IPv6 is available and ctrl channel is IPv6.
      *  - EPSV 1    is used if EPSV 2 (IPv6) fails or is not available or ctrl channel is IPv4.
      *  - PASV      is used if EPSV 1 fails.
      */
    switch (ftpState->state) {
    case SENT_EPSV_ALL: /* EPSV ALL resulted in a bad response. Try ther EPSV methods. */
        ftpState->flags.epsv_all_sent = true;
        if (ftpState->ctrl.conn->local.IsIPv6()) {
            debugs(9, 5, HERE << "FTP Channel is IPv6 (" << ftpState->ctrl.conn->remote << ") attempting EPSV 2 after EPSV ALL has failed.");
            snprintf(cbuf, CTRL_BUFLEN, "EPSV 2\r\n");
            ftpState->state = SENT_EPSV_2;
            break;
        }
        // else fall through to skip EPSV 2

    case SENT_EPSV_2: /* EPSV IPv6 failed. Try EPSV IPv4 */
        if (ftpState->ctrl.conn->local.IsIPv4()) {
            debugs(9, 5, HERE << "FTP Channel is IPv4 (" << ftpState->ctrl.conn->remote << ") attempting EPSV 1 after EPSV ALL has failed.");
            snprintf(cbuf, CTRL_BUFLEN, "EPSV 1\r\n");
            ftpState->state = SENT_EPSV_1;
            break;
        } else if (ftpState->flags.epsv_all_sent) {
            debugs(9, DBG_IMPORTANT, "FTP does not allow PASV method after 'EPSV ALL' has been sent.");
            ftpFail(ftpState);
            return;
        }
        // else fall through to skip EPSV 1

    case SENT_EPSV_1: /* EPSV options exhausted. Try PASV now. */
        debugs(9, 5, HERE << "FTP Channel (" << ftpState->ctrl.conn->remote << ") rejects EPSV connection attempts. Trying PASV instead.");
        snprintf(cbuf, CTRL_BUFLEN, "PASV\r\n");
        ftpState->state = SENT_PASV;
        break;

    default:
        if (!Config.Ftp.epsv) {
            debugs(9, 5, HERE << "EPSV support manually disabled. Sending PASV for FTP Channel (" << ftpState->ctrl.conn->remote <<")");
            snprintf(cbuf, CTRL_BUFLEN, "PASV\r\n");
            ftpState->state = SENT_PASV;
        } else if (Config.Ftp.epsv_all) {
            debugs(9, 5, HERE << "EPSV ALL manually enabled. Attempting with FTP Channel (" << ftpState->ctrl.conn->remote <<")");
            snprintf(cbuf, CTRL_BUFLEN, "EPSV ALL\r\n");
            ftpState->state = SENT_EPSV_ALL;
            /* block other non-EPSV connections being attempted */
            ftpState->flags.epsv_all_sent = true;
        } else {
            if (ftpState->ctrl.conn->local.IsIPv6()) {
                debugs(9, 5, HERE << "FTP Channel (" << ftpState->ctrl.conn->remote << "). Sending default EPSV 2");
                snprintf(cbuf, CTRL_BUFLEN, "EPSV 2\r\n");
                ftpState->state = SENT_EPSV_2;
            }
            if (ftpState->ctrl.conn->local.IsIPv4()) {
                debugs(9, 5, HERE << "Channel (" << ftpState->ctrl.conn->remote <<"). Sending default EPSV 1");
                snprintf(cbuf, CTRL_BUFLEN, "EPSV 1\r\n");
                ftpState->state = SENT_EPSV_1;
            }
        }
        break;
    }

    ftpState->writeCommand(cbuf);

    /*
     * ugly hack for ftp servers like ftp.netscape.com that sometimes
     * dont acknowledge PASV commands. Use connect timeout to be faster then read timeout (minutes).
     */
    typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(9, 5,
                                      TimeoutDialer, ftpState, FtpStateData::ftpTimeout);
    commSetConnTimeout(ftpState->ctrl.conn, Config.Timeout.connect, timeoutCall);
}

void
FtpStateData::processHeadResponse()
{
    debugs(9, 5, HERE << "handling HEAD response");
    ftpSendQuit(this);
    appendSuccessHeader();

    /*
     * On rare occasions I'm seeing the entry get aborted after
     * ftpReadControlReply() and before here, probably when
     * trying to write to the client.
     */
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted while processing HEAD");
        return;
    }

#if USE_ADAPTATION
    if (adaptationAccessCheckPending) {
        debugs(9,3, HERE << "returning due to adaptationAccessCheckPending");
        return;
    }
#endif

    // processReplyBody calls serverComplete() since there is no body
    processReplyBody();
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadPasv(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    int h1, h2, h3, h4;
    int p1, p2;
    int n;
    unsigned short port;
    Ip::Address ipa_remote;
    char *buf;
    LOCAL_ARRAY(char, ipaddr, 1024);
    debugs(9, 3, HERE);

    if (code != 227) {
        debugs(9, 2, "PASV not supported by remote end");
        ftpSendEPRT(ftpState);
        return;
    }

    /*  227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).  */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debugs(9, 5, HERE << "scanning: " << ftpState->ctrl.last_reply);

    buf = ftpState->ctrl.last_reply + strcspn(ftpState->ctrl.last_reply, "0123456789");

    n = sscanf(buf, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2);

    if (n != 6 || p1 < 0 || p2 < 0 || p1 > 255 || p2 > 255) {
        debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
               ftpState->ctrl.conn->remote << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendEPRT(ftpState);
        return;
    }

    snprintf(ipaddr, 1024, "%d.%d.%d.%d", h1, h2, h3, h4);

    ipa_remote = ipaddr;

    if ( ipa_remote.IsAnyAddr() ) {
        debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
               ftpState->ctrl.conn->remote << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendEPRT(ftpState);
        return;
    }

    port = ((p1 << 8) + p2);

    if (0 == port) {
        debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
               ftpState->ctrl.conn->remote << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendEPRT(ftpState);
        return;
    }

    if (Config.Ftp.sanitycheck) {
        if (port < 1024) {
            debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
                   ftpState->ctrl.conn->remote << ": " <<
                   ftpState->ctrl.last_reply);

            ftpSendEPRT(ftpState);
            return;
        }
    }

    ftpState->data.port = port;

    safe_free(ftpState->data.host);
    if (Config.Ftp.sanitycheck)
        ftpState->data.host = xstrdup(fd_table[ftpState->ctrl.conn->fd].ipaddr);
    else
        ftpState->data.host = xstrdup(ipaddr);

    safe_free(ftpState->ctrl.last_command);

    safe_free(ftpState->ctrl.last_reply);

    ftpState->ctrl.last_command = xstrdup("Connect to server data port");

    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->local = ftpState->ctrl.conn->local;
    conn->local.SetPort(0);
    conn->remote = ipaddr;
    conn->remote.SetPort(port);

    debugs(9, 3, HERE << "connecting to " << conn->remote);

    ftpState->data.opener = commCbCall(9,3, "FtpStateData::ftpPasvCallback", CommConnectCbPtrFun(FtpStateData::ftpPasvCallback, ftpState));
    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, ftpState->data.opener, Config.Timeout.connect);
    cs->setHost(ftpState->data.host);
    AsyncJob::Start(cs);
}

void
FtpStateData::ftpPasvCallback(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
{
    FtpStateData *ftpState = (FtpStateData *)data;
    debugs(9, 3, HERE);
    ftpState->data.opener = NULL;

    if (status != COMM_OK) {
        debugs(9, 2, HERE << "Failed to connect. Retrying via another method.");

        // ABORT on timeouts. server may be waiting on a broken TCP link.
        if (status == COMM_TIMEOUT)
            ftpState->writeCommand("ABOR");

        // try another connection attempt with some other method
        ftpSendPassive(ftpState);
        return;
    }

    ftpState->data.opened(conn, ftpState->dataCloser());
    ftpRestOrList(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpOpenListenSocket(FtpStateData * ftpState, int fallback)
{
    /// Close old data channels, if any. We may open a new one below.
    if (ftpState->data.conn != NULL) {
        if ((ftpState->data.conn->flags & COMM_REUSEADDR))
            // NP: in fact it points to the control channel. just clear it.
            ftpState->data.clear();
        else
            ftpState->data.close();
    }
    safe_free(ftpState->data.host);

    /*
     * Set up a listen socket on the same local address as the
     * control connection.
     */
    Comm::ConnectionPointer temp = new Comm::Connection;
    temp->local = ftpState->ctrl.conn->local;

    /*
     * REUSEADDR is needed in fallback mode, since the same port is
     * used for both control and data.
     */
    if (fallback) {
        int on = 1;
        setsockopt(ftpState->ctrl.conn->fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
        ftpState->ctrl.conn->flags |= COMM_REUSEADDR;
        temp->flags |= COMM_REUSEADDR;
    } else {
        /* if not running in fallback mode a new port needs to be retrieved */
        temp->local.SetPort(0);
    }

    ftpState->listenForDataChannel(temp, ftpState->entry->url());
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendPORT(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendPort"))
        return;

    if (Config.Ftp.epsv_all && ftpState->flags.epsv_all_sent) {
        debugs(9, DBG_IMPORTANT, "FTP does not allow PORT method after 'EPSV ALL' has been sent.");
        return;
    }

    debugs(9, 3, HERE);
    ftpState->flags.pasv_supported = 0;
    ftpOpenListenSocket(ftpState, 0);

    if (!Comm::IsConnOpen(ftpState->data.listenConn)) {
        if ( ftpState->data.listenConn != NULL && !ftpState->data.listenConn->local.IsIPv4() ) {
            /* non-IPv4 CANNOT send PORT command.                       */
            /* we got here by attempting and failing an EPRT            */
            /* using the same reply code should simulate a PORT failure */
            ftpReadPORT(ftpState);
            return;
        }

        /* XXX Need to set error message */
        ftpFail(ftpState);
        return;
    }

    // pull out the internal IP address bytes to send in PORT command...
    // source them from the listen_conn->local

    struct addrinfo *AI = NULL;
    ftpState->data.listenConn->local.GetAddrInfo(AI, AF_INET);
    unsigned char *addrptr = (unsigned char *) &((struct sockaddr_in*)AI->ai_addr)->sin_addr;
    unsigned char *portptr = (unsigned char *) &((struct sockaddr_in*)AI->ai_addr)->sin_port;
    snprintf(cbuf, CTRL_BUFLEN, "PORT %d,%d,%d,%d,%d,%d\r\n",
             addrptr[0], addrptr[1], addrptr[2], addrptr[3],
             portptr[0], portptr[1]);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_PORT;

    ftpState->data.listenConn->local.FreeAddrInfo(AI);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadPORT(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code != 200) {
        /* Fall back on using the same port as the control connection */
        debugs(9, 3, "PORT not supported by remote end");
        ftpOpenListenSocket(ftpState, 1);
    }

    ftpRestOrList(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendEPRT(FtpStateData * ftpState)
{
    if (Config.Ftp.epsv_all && ftpState->flags.epsv_all_sent) {
        debugs(9, DBG_IMPORTANT, "FTP does not allow EPRT method after 'EPSV ALL' has been sent.");
        return;
    }

    if (!Config.Ftp.eprt) {
        /* Disabled. Switch immediately to attempting old PORT command. */
        debugs(9, 3, "EPRT disabled by local administrator");
        ftpSendPORT(ftpState);
        return;
    }

    debugs(9, 3, HERE);
    ftpState->flags.pasv_supported = 0;

    ftpOpenListenSocket(ftpState, 0);
    debugs(9, 3, "Listening for FTP data connection with FD " << ftpState->data.conn);
    if (!Comm::IsConnOpen(ftpState->data.conn)) {
        /* XXX Need to set error message */
        ftpFail(ftpState);
        return;
    }

    char buf[MAX_IPSTRLEN];

    /* RFC 2428 defines EPRT as IPv6 equivalent to IPv4 PORT command. */
    /* Which can be used by EITHER protocol. */
    snprintf(cbuf, CTRL_BUFLEN, "EPRT |%d|%s|%d|\r\n",
             ( ftpState->data.listenConn->local.IsIPv6() ? 2 : 1 ),
             ftpState->data.listenConn->local.NtoA(buf,MAX_IPSTRLEN),
             ftpState->data.listenConn->local.GetPort() );

    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_EPRT;
}

static void
ftpReadEPRT(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code != 200) {
        /* Failover to attempting old PORT command. */
        debugs(9, 3, "EPRT not supported by remote end");
        ftpSendPORT(ftpState);
        return;
    }

    ftpRestOrList(ftpState);
}

/**
 \ingroup ServerProtocolFTPInternal
 \par
 * "read" handler to accept FTP data connections.
 *
 \param io    comm accept(2) callback parameters
 */
void
FtpStateData::ftpAcceptDataConnection(const CommAcceptCbParams &io)
{
    debugs(9, 3, HERE);

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted when accepting data conn");
        data.listenConn->close();
        data.listenConn = NULL;
        return;
    }

    if (io.flag != COMM_OK) {
        data.listenConn->close();
        data.listenConn = NULL;
        debugs(9, DBG_IMPORTANT, "FTP AcceptDataConnection: " << io.conn << ": " << xstrerr(io.xerrno));
        /** \todo Need to send error message on control channel*/
        ftpFail(this);
        return;
    }

    /* data listening conn is no longer even open. abort. */
    if (!Comm::IsConnOpen(data.listenConn)) {
        data.listenConn = NULL; // ensure that it's cleared and not just closed.
        return;
    }

    /* data listening conn is no longer even open. abort. */
    if (!Comm::IsConnOpen(data.conn)) {
        data.clear(); // ensure that it's cleared and not just closed.
        return;
    }

    /** \par
     * When squid.conf ftp_sanitycheck is enabled, check the new connection is actually being
     * made by the remote client which is connected to the FTP control socket.
     * Or the one which we were told to listen for by control channel messages (may differ under NAT).
     * This prevents third-party hacks, but also third-party load balancing handshakes.
     */
    if (Config.Ftp.sanitycheck) {
        // accept if either our data or ctrl connection is talking to this remote peer.
        if (data.conn->remote != io.conn->remote && ctrl.conn->remote != io.conn->remote) {
            debugs(9, DBG_IMPORTANT,
                   "FTP data connection from unexpected server (" <<
                   io.conn->remote << "), expecting " <<
                   data.conn->remote << " or " << ctrl.conn->remote);

            /* close the bad sources connection down ASAP. */
            io.conn->close();

            /* drop the bad connection (io) by ignoring the attempt. */
            return;
        }
    }

    /** On COMM_OK start using the accepted data socket and discard the temporary listen socket. */
    data.close();
    data.opened(io.conn, dataCloser());
    static char ntoapeer[MAX_IPSTRLEN];
    io.conn->remote.NtoA(ntoapeer,sizeof(ntoapeer));
    data.host = xstrdup(ntoapeer);

    debugs(9, 3, HERE << "Connected data socket on " <<
           io.conn << ". FD table says: " <<
           "ctrl-peer= " << fd_table[ctrl.conn->fd].ipaddr << ", " <<
           "data-peer= " << fd_table[data.conn->fd].ipaddr);

    assert(haveControlChannel("ftpAcceptDataConnection"));
    assert(ctrl.message == NULL);

    // Ctrl channel operations will determine what happens to this data connection
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpRestOrList(FtpStateData * ftpState)
{
    debugs(9, 3, HERE);

    if (ftpState->typecode == 'D') {
        ftpState->flags.isdir = 1;

        if (ftpState->flags.put) {
            ftpSendMkdir(ftpState);	/* PUT name;type=d */
        } else {
            ftpSendNlst(ftpState);	/* GET name;type=d  sec 3.2.2 of RFC 1738 */
        }
    } else if (ftpState->flags.put) {
        ftpSendStor(ftpState);
    } else if (ftpState->flags.isdir)
        ftpSendList(ftpState);
    else if (ftpState->restartable())
        ftpSendRest(ftpState);
    else
        ftpSendRetr(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendStor(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendStor"))
        return;

    debugs(9, 3, HERE);

    if (ftpState->filepath != NULL) {
        /* Plain file upload */
        snprintf(cbuf, CTRL_BUFLEN, "STOR %s\r\n", ftpState->filepath);
        ftpState->writeCommand(cbuf);
        ftpState->state = SENT_STOR;
    } else if (ftpState->request->header.getInt64(HDR_CONTENT_LENGTH) > 0) {
        /* File upload without a filename. use STOU to generate one */
        snprintf(cbuf, CTRL_BUFLEN, "STOU\r\n");
        ftpState->writeCommand(cbuf);
        ftpState->state = SENT_STOR;
    } else {
        /* No file to transfer. Only create directories if needed */
        ftpSendReply(ftpState);
    }
}

/// \ingroup ServerProtocolFTPInternal
/// \deprecated use ftpState->readStor() instead.
static void
ftpReadStor(FtpStateData * ftpState)
{
    ftpState->readStor();
}

void FtpStateData::readStor()
{
    int code = ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && Comm::IsConnOpen(data.conn))) {
        if (!startRequestBodyFlow()) { // register to receive body data
            ftpFail(this);
            return;
        }

        /* When client status is 125, or 150 and the data connection is open, Begin data transfer. */
        debugs(9, 3, HERE << "starting data transfer");
        switchTimeoutToDataChannel();
        sendMoreRequestBody();
        fwd->dontRetry(true); // dont permit re-trying if the body was sent.
        state = WRITING_DATA;
        debugs(9, 3, HERE << "writing data channel");
    } else if (code == 150) {
        /* When client code is 150 with no data channel, Accept data channel. */
        debugs(9, 3, "ftpReadStor: accepting data channel");
        listenForDataChannel(data.conn, data.host);
    } else {
        debugs(9, DBG_IMPORTANT, HERE << "Unexpected reply code "<< std::setfill('0') << std::setw(3) << code);
        ftpFail(this);
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendRest(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendRest"))
        return;

    debugs(9, 3, HERE);

    snprintf(cbuf, CTRL_BUFLEN, "REST %" PRId64 "\r\n", ftpState->restart_offset);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_REST;
}

int
FtpStateData::restartable()
{
    if (restart_offset > 0)
        return 1;

    if (!request->range)
        return 0;

    if (!flags.binary)
        return 0;

    if (theSize <= 0)
        return 0;

    int64_t desired_offset = request->range->lowestOffset(theSize);

    if (desired_offset <= 0)
        return 0;

    if (desired_offset >= theSize)
        return 0;

    restart_offset = desired_offset;
    return 1;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadRest(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);
    assert(ftpState->restart_offset > 0);

    if (code == 350) {
        ftpState->setCurrentOffset(ftpState->restart_offset);
        ftpSendRetr(ftpState);
    } else if (code > 0) {
        debugs(9, 3, HERE << "REST not supported");
        ftpState->flags.rest_supported = 0;
        ftpSendRetr(ftpState);
    } else {
        ftpFail(ftpState);
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendList(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendList"))
        return;

    debugs(9, 3, HERE);

    if (ftpState->filepath) {
        snprintf(cbuf, CTRL_BUFLEN, "LIST %s\r\n", ftpState->filepath);
    } else {
        snprintf(cbuf, CTRL_BUFLEN, "LIST\r\n");
    }

    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_LIST;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendNlst(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendNlst"))
        return;

    debugs(9, 3, HERE);

    ftpState->flags.tried_nlst = 1;

    if (ftpState->filepath) {
        snprintf(cbuf, CTRL_BUFLEN, "NLST %s\r\n", ftpState->filepath);
    } else {
        snprintf(cbuf, CTRL_BUFLEN, "NLST\r\n");
    }

    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_NLST;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadList(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && Comm::IsConnOpen(ftpState->data.conn))) {
        /* Begin data transfer */
        debugs(9, 3, HERE << "begin data transfer from " << ftpState->data.conn->remote << " (" << ftpState->data.conn->local << ")");
        ftpState->switchTimeoutToDataChannel();
        ftpState->maybeReadVirginBody();
        ftpState->state = READING_DATA;
        return;
    } else if (code == 150) {
        /* Accept data channel */
        debugs(9, 3, HERE << "accept data channel from " << ftpState->data.conn->remote << " (" << ftpState->data.conn->local << ")");
        ftpState->listenForDataChannel(ftpState->data.conn, ftpState->data.host);
        return;
    } else if (!ftpState->flags.tried_nlst && code > 300) {
        ftpSendNlst(ftpState);
    } else {
        ftpFail(ftpState);
        return;
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendRetr(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendRetr"))
        return;

    debugs(9, 3, HERE);

    assert(ftpState->filepath != NULL);
    snprintf(cbuf, CTRL_BUFLEN, "RETR %s\r\n", ftpState->filepath);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_RETR;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadRetr(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && Comm::IsConnOpen(ftpState->data.conn))) {
        /* Begin data transfer */
        debugs(9, 3, HERE << "begin data transfer from " << ftpState->data.conn->remote << " (" << ftpState->data.conn->local << ")");
        ftpState->switchTimeoutToDataChannel();
        ftpState->maybeReadVirginBody();
        ftpState->state = READING_DATA;
    } else if (code == 150) {
        /* Accept data channel */
        ftpState->listenForDataChannel(ftpState->data.conn, ftpState->data.host);
    } else if (code >= 300) {
        if (!ftpState->flags.try_slash_hack) {
            /* Try this as a directory missing trailing slash... */
            ftpState->hackShortcut(ftpSendCwd);
        } else {
            ftpFail(ftpState);
        }
    } else {
        ftpFail(ftpState);
    }
}

/**
 * Generate the HTTP headers and template fluff around an FTP
 * directory listing display.
 */
void
FtpStateData::completedListing()
{
    assert(entry);
    entry->lock();
    ErrorState ferr(ERR_DIR_LISTING, HTTP_OK, request);
    ferr.ftp.listing = &listing;
    ferr.ftp.cwd_msg = xstrdup(cwd_message.size()? cwd_message.termedBuf() : "");
    ferr.ftp.server_msg = ctrl.message;
    ctrl.message = NULL;
    entry->replaceHttpReply( ferr.BuildHttpReply() );
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->flush();
    entry->unlock();
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadTransferDone(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 226 || code == 250) {
        /* Connection closed; retrieval done. */
        if (ftpState->flags.listing) {
            ftpState->completedListing();
            /* QUIT operation handles sending the reply to client */
        }
        ftpSendQuit(ftpState);
    } else {			/* != 226 */
        debugs(9, DBG_IMPORTANT, HERE << "Got code " << code << " after reading data");
        ftpState->failed(ERR_FTP_FAILURE, 0);
        /* failed closes ctrl.conn and frees ftpState */
        return;
    }
}

// premature end of the request body
void
FtpStateData::handleRequestBodyProducerAborted()
{
    ServerStateData::handleRequestBodyProducerAborted();
    debugs(9, 3, HERE << "ftpState=" << this);
    failed(ERR_READ_ERROR, 0);
}

/**
 * This will be called when the put write is completed
 */
void
FtpStateData::sentRequestBody(const CommIoCbParams &io)
{
    if (io.size > 0)
        kb_incr(&(statCounter.server.ftp.kbytes_out), io.size);
    ServerStateData::sentRequestBody(io);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpWriteTransferDone(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (!(code == 226 || code == 250)) {
        debugs(9, DBG_IMPORTANT, HERE << "Got code " << code << " after sending data");
        ftpState->failed(ERR_FTP_PUT_ERROR, 0);
        return;
    }

    ftpState->entry->timestampsSet();	/* XXX Is this needed? */
    ftpSendReply(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendQuit(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendQuit"))
        return;

    snprintf(cbuf, CTRL_BUFLEN, "QUIT\r\n");
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_QUIT;
}

/**
 * \ingroup ServerProtocolFTPInternal
 *
 *  This completes a client FTP operation with success or other page
 *  generated and stored in the entry field by the code issuing QUIT.
 */
static void
ftpReadQuit(FtpStateData * ftpState)
{
    ftpState->serverComplete();
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpTrySlashHack(FtpStateData * ftpState)
{
    char *path;
    ftpState->flags.try_slash_hack = 1;
    /* Free old paths */

    debugs(9, 3, HERE);

    if (ftpState->pathcomps)
        wordlistDestroy(&ftpState->pathcomps);

    safe_free(ftpState->filepath);

    /* Build the new path (urlpath begins with /) */
    path = xstrdup(ftpState->request->urlpath.termedBuf());

    rfc1738_unescape(path);

    ftpState->filepath = path;

    /* And off we go */
    ftpGetFile(ftpState);
}

/**
 * Forget hack status. Next error is shown to the user
 */
void
FtpStateData::unhack()
{
    debugs(9, 3, HERE);

    if (old_request != NULL) {
        safe_free(old_request);
        safe_free(old_reply);
    }
}

void
FtpStateData::hackShortcut(FTPSM * nextState)
{
    /* Clear some unwanted state */
    setCurrentOffset(0);
    restart_offset = 0;
    /* Save old error message & some state info */

    debugs(9, 3, HERE);

    if (old_request == NULL) {
        old_request = ctrl.last_command;
        ctrl.last_command = NULL;
        old_reply = ctrl.last_reply;
        ctrl.last_reply = NULL;

        if (pathcomps == NULL && filepath != NULL)
            old_filepath = xstrdup(filepath);
    }

    /* Jump to the "hack" state */
    nextState(this);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpFail(FtpStateData *ftpState)
{
    debugs(9, 6, HERE << "flags(" <<
           (ftpState->flags.isdir?"IS_DIR,":"") <<
           (ftpState->flags.try_slash_hack?"TRY_SLASH_HACK":"") << "), " <<
           "mdtm=" << ftpState->mdtm << ", size=" << ftpState->theSize <<
           "slashhack=" << (ftpState->request->urlpath.caseCmp("/%2f", 4)==0? "T":"F") );

    /* Try the / hack to support "Netscape" FTP URL's for retreiving files */
    if (!ftpState->flags.isdir &&	/* Not a directory */
            !ftpState->flags.try_slash_hack &&	/* Not in slash hack */
            ftpState->mdtm <= 0 && ftpState->theSize < 0 &&	/* Not known as a file */
            ftpState->request->urlpath.caseCmp("/%2f", 4) != 0) {	/* No slash encoded */

        switch (ftpState->state) {

        case SENT_CWD:

        case SENT_RETR:
            /* Try the / hack */
            ftpState->hackShortcut(ftpTrySlashHack);
            return;

        default:
            break;
        }
    }

    ftpState->failed(ERR_NONE, 0);
    /* failed() closes ctrl.conn and frees this */
}

void
FtpStateData::failed(err_type error, int xerrno)
{
    debugs(9,3,HERE << "entry-null=" << (entry?entry->isEmpty():0) << ", entry=" << entry);
    if (entry->isEmpty())
        failedErrorMessage(error, xerrno);

    serverComplete();
}

void
FtpStateData::failedErrorMessage(err_type error, int xerrno)
{
    ErrorState *ftperr = NULL;
    const char *command, *reply;

    /* Translate FTP errors into HTTP errors */
    switch (error) {

    case ERR_NONE:

        switch (state) {

        case SENT_USER:

        case SENT_PASS:

            if (ctrl.replycode > 500)
                if (password_url)
                    ftperr = new ErrorState(ERR_FTP_FORBIDDEN, HTTP_FORBIDDEN, fwd->request);
                else
                    ftperr = new ErrorState(ERR_FTP_FORBIDDEN, HTTP_UNAUTHORIZED, fwd->request);

            else if (ctrl.replycode == 421)
                ftperr = new ErrorState(ERR_FTP_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE, fwd->request);

            break;

        case SENT_CWD:

        case SENT_RETR:
            if (ctrl.replycode == 550)
                ftperr = new ErrorState(ERR_FTP_NOT_FOUND, HTTP_NOT_FOUND, fwd->request);

            break;

        default:
            break;
        }

        break;

    case ERR_READ_TIMEOUT:
        ftperr = new ErrorState(error, HTTP_GATEWAY_TIMEOUT, fwd->request);
        break;

    default:
        ftperr = new ErrorState(error, HTTP_BAD_GATEWAY, fwd->request);
        break;
    }

    if (ftperr == NULL)
        ftperr = new ErrorState(ERR_FTP_FAILURE, HTTP_BAD_GATEWAY, fwd->request);

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

    entry->replaceHttpReply( ftperr->BuildHttpReply() );
    delete ftperr;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendReply(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    http_status http_code;
    err_type err_code = ERR_NONE;

    debugs(9, 3, HERE << ftpState->entry->url() << ", code " << code);

    if (cbdataReferenceValid(ftpState))
        debugs(9, 5, HERE << "ftpState (" << ftpState << ") is valid!");

    if (code == 226 || code == 250) {
        err_code = (ftpState->mdtm > 0) ? ERR_FTP_PUT_MODIFIED : ERR_FTP_PUT_CREATED;
        http_code = (ftpState->mdtm > 0) ? HTTP_ACCEPTED : HTTP_CREATED;
    } else if (code == 227) {
        err_code = ERR_FTP_PUT_CREATED;
        http_code = HTTP_CREATED;
    } else {
        err_code = ERR_FTP_PUT_ERROR;
        http_code = HTTP_INTERNAL_SERVER_ERROR;
    }

    ErrorState err(err_code, http_code, ftpState->request);

    if (ftpState->old_request)
        err.ftp.request = xstrdup(ftpState->old_request);
    else
        err.ftp.request = xstrdup(ftpState->ctrl.last_command);

    if (ftpState->old_reply)
        err.ftp.reply = xstrdup(ftpState->old_reply);
    else if (ftpState->ctrl.last_reply)
        err.ftp.reply = xstrdup(ftpState->ctrl.last_reply);
    else
        err.ftp.reply = xstrdup("");

    // TODO: interpret as FTP-specific error code
    err.detailError(code);

    ftpState->entry->replaceHttpReply( err.BuildHttpReply() );

    ftpSendQuit(ftpState);
}

void
FtpStateData::appendSuccessHeader()
{
    const char *mime_type = NULL;
    const char *mime_enc = NULL;
    String urlpath = request->urlpath;
    const char *filename = NULL;
    const char *t = NULL;

    debugs(9, 3, HERE);

    if (flags.http_header_sent)
        return;

    HttpReply *reply = new HttpReply;

    flags.http_header_sent = 1;

    assert(entry->isEmpty());

    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);

    entry->buffer();	/* released when done processing current data payload */

    filename = (t = urlpath.rpos('/')) ? t + 1 : urlpath.termedBuf();

    if (flags.isdir) {
        mime_type = "text/html";
    } else {
        switch (typecode) {

        case 'I':
            mime_type = "application/octet-stream";
            mime_enc = mimeGetContentEncoding(filename);
            break;

        case 'A':
            mime_type = "text/plain";
            break;

        default:
            mime_type = mimeGetContentType(filename);
            mime_enc = mimeGetContentEncoding(filename);
            break;
        }
    }

    /* set standard stuff */

    if (0 == getCurrentOffset()) {
        /* Full reply */
        reply->setHeaders(HTTP_OK, "Gatewaying", mime_type, theSize, mdtm, -2);
    } else if (theSize < getCurrentOffset()) {
        /*
         * DPW 2007-05-04
         * offset should not be larger than theSize.  We should
         * not be seeing this condition any more because we'll only
         * send REST if we know the theSize and if it is less than theSize.
         */
        debugs(0,DBG_CRITICAL,HERE << "Whoops! " <<
               " current offset=" << getCurrentOffset() <<
               ", but theSize=" << theSize <<
               ".  assuming full content response");
        reply->setHeaders(HTTP_OK, "Gatewaying", mime_type, theSize, mdtm, -2);
    } else {
        /* Partial reply */
        HttpHdrRangeSpec range_spec;
        range_spec.offset = getCurrentOffset();
        range_spec.length = theSize - getCurrentOffset();
        reply->setHeaders(HTTP_PARTIAL_CONTENT, "Gatewaying", mime_type, theSize - getCurrentOffset(), mdtm, -2);
        httpHeaderAddContRange(&reply->header, range_spec, theSize);
    }

    /* additional info */
    if (mime_enc)
        reply->header.putStr(HDR_CONTENT_ENCODING, mime_enc);

    setVirginReply(reply);
    adaptOrFinalizeReply();
}

void
FtpStateData::haveParsedReplyHeaders()
{
    ServerStateData::haveParsedReplyHeaders();

    StoreEntry *e = entry;

    e->timestampsSet();

    if (flags.authenticated) {
        /*
         * Authenticated requests can't be cached.
         */
        e->release();
    } else if (EBIT_TEST(e->flags, ENTRY_CACHABLE) && !getCurrentOffset()) {
        e->setPublicKey();
    } else {
        e->release();
    }
}

HttpReply *
FtpStateData::ftpAuthRequired(HttpRequest * request, const char *realm)
{
    ErrorState err(ERR_CACHE_ACCESS_DENIED, HTTP_UNAUTHORIZED, request);
    HttpReply *newrep = err.BuildHttpReply();
#if HAVE_AUTH_MODULE_BASIC
    /* add Authenticate header */
    newrep->header.putAuth("Basic", realm);
#endif
    return newrep;
}

/**
 \ingroup ServerProtocolFTPAPI
 \todo Should be a URL class API call.
 *
 *  Construct an URI with leading / in PATH portion for use by CWD command
 *  possibly others. FTP encodes absolute paths as beginning with '/'
 *  after the initial URI path delimiter, which happens to be / itself.
 *  This makes FTP absolute URI appear as:  ftp:host:port//root/path
 *  To encompass older software which compacts multiple // to / in transit
 *  We use standard URI-encoding on the second / making it
 *  ftp:host:port/%2froot/path  AKA 'the FTP %2f hack'.
 */
const char *
ftpUrlWith2f(HttpRequest * request)
{
    String newbuf = "%2f";

    if (request->protocol != AnyP::PROTO_FTP)
        return NULL;

    if ( request->urlpath[0]=='/' ) {
        newbuf.append(request->urlpath);
        request->urlpath.absorb(newbuf);
        safe_free(request->canonical);
    } else if ( !strncmp(request->urlpath.termedBuf(), "%2f", 3) ) {
        newbuf.append(request->urlpath.substr(1,request->urlpath.size()));
        request->urlpath.absorb(newbuf);
        safe_free(request->canonical);
    }

    return urlCanonical(request);
}

void
FtpStateData::printfReplyBody(const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    static char buf[4096];
    buf[0] = '\0';
    vsnprintf(buf, 4096, fmt, args);
    writeReplyBody(buf, strlen(buf));
    va_end(args);
}

/**
 * Call this when there is data from the origin server
 * which should be sent to either StoreEntry, or to ICAP...
 */
void
FtpStateData::writeReplyBody(const char *dataToWrite, size_t dataLength)
{
    debugs(9, 5, HERE << "writing " << dataLength << " bytes to the reply");
    addVirginReplyBody(dataToWrite, dataLength);
}

/**
 * called after we wrote the last byte of the request body
 */
void
FtpStateData::doneSendingRequestBody()
{
    ServerStateData::doneSendingRequestBody();
    debugs(9,3, HERE);
    dataComplete();
    /* NP: RFC 959  3.3.  DATA CONNECTION MANAGEMENT
     * if transfer type is 'stream' call dataComplete()
     * otherwise leave open. (reschedule control channel read?)
     */
}

/**
 * A hack to ensure we do not double-complete on the forward entry.
 *
 \todo FtpStateData logic should probably be rewritten to avoid
 *	double-completion or FwdState should be rewritten to allow it.
 */
void
FtpStateData::completeForwarding()
{
    if (fwd == NULL || flags.completed_forwarding) {
        debugs(9, 3, HERE << "completeForwarding avoids " <<
               "double-complete on FD " << ctrl.conn->fd << ", Data FD " << data.conn->fd <<
               ", this " << this << ", fwd " << fwd);
        return;
    }

    flags.completed_forwarding = true;
    ServerStateData::completeForwarding();
}

/**
 * Close the FTP server connection(s). Used by serverComplete().
 */
void
FtpStateData::closeServer()
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
FtpStateData::doneWithServer() const
{
    return !Comm::IsConnOpen(ctrl.conn) && !Comm::IsConnOpen(data.conn);
}

/**
 * Have we lost the FTP server control channel?
 *
 \retval true	The server control channel is available.
 \retval false	The server control channel is not available.
 */
bool
FtpStateData::haveControlChannel(const char *caller_name) const
{
    if (doneWithServer())
        return false;

    /* doneWithServer() only checks BOTH channels are closed. */
    if (!Comm::IsConnOpen(ctrl.conn)) {
        debugs(9, DBG_IMPORTANT, "WARNING! FTP Server Control channel is closed, but Data channel still active.");
        debugs(9, 2, caller_name << ": attempted on a closed FTP channel.");
        return false;
    }

    return true;
}

/**
 * Quickly abort the transaction
 *
 \todo destruction should be sufficient as the destructor should cleanup,
 *	including canceling close handlers
 */
void
FtpStateData::abortTransaction(const char *reason)
{
    debugs(9, 3, HERE << "aborting transaction for " << reason <<
           "; FD " << (ctrl.conn!=NULL?ctrl.conn->fd:-1) << ", Data FD " << (data.conn!=NULL?data.conn->fd:-1) << ", this " << this);
    if (Comm::IsConnOpen(ctrl.conn)) {
        ctrl.conn->close();
        return;
    }

    fwd->handleUnregisteredServerEnd();
    mustStop("FtpStateData::abortTransaction");
}

/// creates a data channel Comm close callback
AsyncCall::Pointer
FtpStateData::dataCloser()
{
    typedef CommCbMemFunT<FtpStateData, CommCloseCbParams> Dialer;
    return JobCallback(9, 5, Dialer, this, FtpStateData::dataClosed);
}

/// configures the channel with a descriptor and registers a close handler
void
FtpChannel::opened(const Comm::ConnectionPointer &newConn, const AsyncCall::Pointer &aCloser)
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
FtpChannel::clear()
{
    conn = NULL;
    closer = NULL;
}
