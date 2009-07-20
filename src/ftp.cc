/*
 * $Id$
 *
 * DEBUG: section 9     File Transfer Protocol (FTP)
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
#include "Store.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "errorpage.h"
#include "fde.h"
#include "comm.h"
#include "HttpHeaderRange.h"
#include "HttpHdrContRange.h"
#include "HttpHeader.h"
#if DELAY_POOLS
#include "DelayPools.h"
#include "MemObject.h"
#endif
#include "ConnectionDetail.h"
#include "forward.h"
#include "Server.h"
#include "MemBuf.h"
#include "wordlist.h"
#include "SquidTime.h"
#include "URLScheme.h"

/**
 \defgroup ServerProtocolFTPInternal Server-Side FTP Internals
 \ingroup ServerProtocolFTPAPI
 */

/// \ingroup ServerProtocolFTPInternal
static const char *const crlf = "\r\n";

/// \ingroup ServerProtocolFTPInternal
static char cbuf[1024];

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
    bool html_header_sent;
    bool binary;
    bool try_slash_hack;
    bool put;
    bool put_mkdir;
    bool listformat_unknown;
    bool listing_started;
    bool completed_forwarding;
};

class FtpStateData;

/// \ingroup ServerProtocolFTPInternal
typedef void (FTPSM) (FtpStateData *);

/// common code for FTP control and data channels
// does not own the channel descriptor, which is managed by FtpStateData
class FtpChannel
{
public:
    FtpChannel(): fd(-1) {}

    /// called after the socket is opened, sets up close handler
    void opened(int aFd, const AsyncCall::Pointer &aCloser);

    void close(); /// clears the close handler and calls comm_close
    void clear(); /// just resets fd and close handler

    int fd; /// channel descriptor; \todo: remove because the closer has it

private:
    AsyncCall::Pointer closer; /// Comm close handler callback
};

/// \ingroup ServerProtocolFTPInternal
class FtpStateData : public ServerStateData
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    void *toCbdata() { return this; }

    FtpStateData(FwdState *);
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
    wordlist *cwd_message;
    char *old_request;
    char *old_reply;
    char *old_filepath;
    char typecode;

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
        u_short port;
        bool read_pending;
    } data;

    struct _ftp_flags flags;

private:
    CBDATA_CLASS(FtpStateData);

public:
    // these should all be private
    void start();
    void loginParser(const char *, int escaped);
    int restartable();
    void appendSuccessHeader();
    void hackShortcut(FTPSM * nextState);
    void failed(err_type, int xerrno);
    void failedErrorMessage(err_type, int xerrno);
    void unhack();
    void listingStart();
    void listingFinish();
    void scheduleReadControlReply(int);
    void handleControlReply();
    void readStor();
    char *htmlifyListEntry(const char *line);
    void parseListing();
    void dataComplete();
    void dataRead(const CommIoCbParams &io);
    int checkAuth(const HttpHeader * req_hdr);
    void checkUrlpath();
    void buildTitleUrl();
    void writeReplyBody(const char *, size_t len);
    void printfReplyBody(const char *fmt, ...);
    virtual int dataDescriptor() const;
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
    ctrl.clear();
    deleteThis("FtpStateData::ctrlClosed");
}

/// handler called by Comm when FTP data channel is closed unexpectedly
void
FtpStateData::dataClosed(const CommCloseCbParams &io)
{
    data.clear();
    failed(ERR_FTP_FAILURE, 0);
    /* failed closes ctrl.fd and frees ftpState */

    /* NP: failure recovery may be possible when its only a data.fd failure.
     *     is the ctrl.fd is still fine, we can send ABOR down it and retry.
     *     Just need to watch out for wider Squid states like shutting down or reconfigure.
     */
}

FtpStateData::FtpStateData(FwdState *theFwdState) : AsyncJob("FtpStateData"), ServerStateData(theFwdState)
{
    const char *url = entry->url();
    debugs(9, 3, HERE << "'" << url << "'" );
    statCounter.server.all.requests++;
    statCounter.server.ftp.requests++;
    theSize = -1;
    mdtm = -1;

    if (Config.Ftp.passive && !theFwdState->ftpPasvFailed())
        flags.pasv_supported = 1;

    flags.rest_supported = 1;

    typedef CommCbMemFunT<FtpStateData, CommCloseCbParams> Dialer;
    AsyncCall::Pointer closer = asyncCall(9, 5, "FtpStateData::ctrlClosed",
                                          Dialer(this, &FtpStateData::ctrlClosed));
    ctrl.opened(theFwdState->server_fd, closer);

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

    data.close();

    if (ctrl.fd >= 0) {
        debugs(9, DBG_IMPORTANT, HERE << "Internal bug: FtpStateData left " <<
               "control FD " << ctrl.fd << " open");
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

    if (cwd_message)
        wordlistDestroy(&cwd_message);

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
 * Produces filled member varisbles user, password, password_url if anything found.
 */
void
FtpStateData::loginParser(const char *login, int escaped)
{
    char *s = NULL;
    debugs(9, 4, HERE << ": login='" << login << "', escaped=" << escaped);
    debugs(9, 9, HERE << ": IN : login='" << login << "', escaped=" << escaped << ", user=" << user << ", password=" << password);

    if ((s = strchr(login, ':'))) {
        *s = '\0';

        /* if there was a username part */
        if (s > login) {
            xstrncpy(user, login, MAX_URL);
            if (escaped)
                rfc1738_unescape(user);
        }

        /* if there was a password part */
        if ( s[1] != '\0' ) {
            xstrncpy(password, s + 1, MAX_URL);
            if (escaped) {
                rfc1738_unescape(password);
                password_url = 1;
            }
        }
    } else if (login[0]) {
        /* no password, just username */
        xstrncpy(user, login, MAX_URL);
        if (escaped)
            rfc1738_unescape(user);
    }

    debugs(9, 9, HERE << ": OUT: login='" << login << "', escaped=" << escaped << ", user=" << user << ", password=" << password);
}

void
FtpStateData::ftpTimeout(const CommTimeoutCbParams &io)
{
    debugs(9, 4, "ftpTimeout: FD " << io.fd << ": '" << entry->url() << "'" );

    if (SENT_PASV == state && io.fd == data.fd) {
        /* stupid ftp.netscape.com */
        fwd->dontRetry(false);
        fwd->ftpPasvFailed(true);
        debugs(9, DBG_IMPORTANT, "ftpTimeout: timeout in SENT_PASV state" );
    }

    failed(ERR_READ_TIMEOUT, 0);
    /* failed() closes ctrl.fd and frees ftpState */
}

void
FtpStateData::listingStart()
{
    debugs(9,3, HERE);
    wordlist *w;
    char *dirup;
    int i, j, k;
    const char *title = title_url.termedBuf();
    flags.listing_started = true;
    printfReplyBody("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");
    printfReplyBody("<!-- HTML listing generated by Squid %s -->\n",
                    version_string);
    printfReplyBody("<!-- %s -->\n", mkrfc1123(squid_curtime));
    printfReplyBody("<HTML><HEAD><TITLE>\n");
    {
        char *t = xstrdup(title);
        rfc1738_unescape(t);
        printfReplyBody("FTP Directory: %s\n", html_quote(t));
        xfree(t);
    }

    printfReplyBody("</TITLE>\n");
    printfReplyBody("<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>\n");

    if (flags.need_base_href)
        printfReplyBody("<BASE HREF=\"%s\">\n",
                        html_quote(base_href.termedBuf()));

    printfReplyBody("</HEAD><BODY>\n");

    if (cwd_message) {
        printfReplyBody("<PRE>\n");

        for (w = cwd_message; w; w = w->next)
            printfReplyBody("%s\n", html_quote(w->key));

        printfReplyBody("</PRE>\n");

        printfReplyBody("<HR noshade size=\"1px\">\n");

        wordlistDestroy(&cwd_message);
    }

    printfReplyBody("<H2>\n");
    printfReplyBody("FTP Directory: ");
    /* "ftp://" == 6 characters */
    assert(title_url.size() >= 6);
    k = 6 + strcspn(&title[6], "/");

    for (i = 6, j = 0; title[i]; j = i) {
        printfReplyBody("<A HREF=\"");
        i += strcspn(&title[i], "/");

        if (i > j) {
            char *url = xstrdup(title);
            url[i] = '\0';
            printfReplyBody("%s", html_quote(url + k));
            printfReplyBody("/");
            printfReplyBody("\">");
            rfc1738_unescape(url + j);
            printfReplyBody("%s", html_quote(url + j));
            safe_free(url);
            printfReplyBody("</A>");
        }

        printfReplyBody("/");

        if (title[i] == '/')
            i++;

        if (i == j) {
            /* Error guard, or "assert" */
            printfReplyBody("ERROR: Failed to parse URL: %s\n",
                            html_quote(title));
            debugs(9, DBG_CRITICAL, "Failed to parse URL: " << title);
            break;
        }
    }

    printfReplyBody("</H2>\n");
    printfReplyBody("<PRE>\n");
    dirup = htmlifyListEntry("<internal-dirup>");
    writeReplyBody(dirup, strlen(dirup));
    flags.html_header_sent = 1;
}

void
FtpStateData::listingFinish()
{
    debugs(9,3,HERE);
    entry->buffer();
    printfReplyBody("</PRE>\n");

    if (flags.listformat_unknown && !flags.tried_nlst) {
        printfReplyBody("<A HREF=\"%s/;type=d\">[As plain directory]</A>\n",
                        flags.dir_slash ? rfc1738_escape_part(old_filepath) : ".");
    } else if (typecode == 'D') {
        const char *path = flags.dir_slash ? filepath : ".";
        printfReplyBody("<A HREF=\"%s/\">[As extended directory]</A>\n", rfc1738_escape_part(path));
    }

    printfReplyBody("<HR noshade size=\"1px\">\n");
    printfReplyBody("<ADDRESS>\n");
    printfReplyBody("Generated %s by %s (%s)\n",
                    mkrfc1123(squid_curtime),
                    getMyHostname(),
                    visible_appname_string);
    printfReplyBody("</ADDRESS></BODY></HTML>\n");
}

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

    for (i = 0; i < 12; i++)
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

    for (t = strtok(xbuf, w_space); t && n_tokens < MAX_TOKENS; t = strtok(NULL, w_space))
        tokens[n_tokens++] = xstrdup(t);

    xfree(xbuf);

    /* locate the Month field */
    for (i = 3; i < n_tokens - 2; i++) {
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
                    copyFrom++;
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
                ct++;

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
            time_t t;
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
                t = (time_t) strtol(ct + 1, &tmp, 0);

                if (tmp != ct + 1)
                    break;	/* not a valid integer */

                p->date = xstrdup(ctime(&t));

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
                ct++;
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

    for (i = 0; i < n_tokens; i++)
        xfree(tokens[i]);

    if (!p->name)
        ftpListPartsFree(&p);	/* cleanup */

    return p;
}

/// \ingroup ServerProtocolFTPInternal
static const char *
dots_fill(size_t len)
{
    static char buf[256];
    size_t i = 0;

    if (len > Config.Ftp.list_width) {
        memset(buf, ' ', 256);
        buf[0] = '\n';
        buf[Config.Ftp.list_width + 4] = '\0';
        return buf;
    }

    for (i = len; i < Config.Ftp.list_width; i++)
        buf[i - len] = (i % 2) ? '.' : ' ';

    buf[i - len] = '\0';

    return buf;
}

char *
FtpStateData::htmlifyListEntry(const char *line)
{
    LOCAL_ARRAY(char, icon, 2048);
    LOCAL_ARRAY(char, href, 2048 + 40);
    LOCAL_ARRAY(char, text, 2048);
    LOCAL_ARRAY(char, size, 2048);
    LOCAL_ARRAY(char, chdir, 2048 + 40);
    LOCAL_ARRAY(char, view, 2048 + 40);
    LOCAL_ARRAY(char, download, 2048 + 40);
    LOCAL_ARRAY(char, link, 2048 + 40);
    LOCAL_ARRAY(char, html, 8192);
    LOCAL_ARRAY(char, prefix, 2048);
    size_t width = Config.Ftp.list_width;
    ftpListParts *parts;
    *icon = *href = *text = *size = *chdir = *view = *download = *link = *html = '\0';

    if ((int) strlen(line) > 1024) {
        snprintf(html, 8192, "%s\n", line);
        return html;
    }

    if (flags.dir_slash && dirpath && typecode != 'D')
        snprintf(prefix, 2048, "%s/", rfc1738_escape_part(dirpath));
    else
        prefix[0] = '\0';

    /* Handle builtin <dirup> */
    if (strcmp(line, "<internal-dirup>") == 0) {
        /* <A HREF="{href}">{icon}</A> <A HREF="{href}">{text}</A> {link} */
        snprintf(icon, 2048, "<IMG border=\"0\" SRC=\"%s\" ALT=\"%-6s\">",
                 mimeGetIconURL("internal-dirup"),
                 "[DIRUP]");

        if (!flags.no_dotdot && !flags.root_dir) {
            /* Normal directory */

            if (!flags.dir_slash)
                strcpy(href, "../");
            else
                strcpy(href, "./");

            strcpy(text, "Parent Directory");
        } else if (!flags.no_dotdot && flags.root_dir) {
            /* "Top level" directory */
            strcpy(href, "%2e%2e/");
            strcpy(text, "Parent Directory");
            snprintf(link, 2048, "(<A HREF=\"%s\">%s</A>)",
                     "%2f/",
                     "Root Directory");
        } else if (flags.no_dotdot && !flags.root_dir) {
            char *url;
            /* Normal directory where last component is / or ..  */
            strcpy(href, "%2e%2e/");
            strcpy(text, "Parent Directory");

            if (flags.dir_slash) {
                url = xstrdup("./");
            } else {
                const char *title = title_url.termedBuf();
                int k = 6 + strcspn(&title[6], "/");
                char *t;
                url = xstrdup(title + k);
                t = url + strlen(url) - 2;

                while (t > url && *t != '/')
                    *t-- = '\0';
            }

            snprintf(link, 2048, "(<A HREF=\"%s\">%s</A>)", url, "Back");
            safe_free(url);
        } else {		/* NO_DOTDOT && ROOT_DIR */
            /* "UNIX Root" directory */
            strcpy(href, "/");
            strcpy(text, "Home Directory");
        }

        snprintf(html, 8192, "<A HREF=\"%s\">%s</A> <A HREF=\"%s\">%s</A> %s\n",
                 href, icon, href, text, link);
        return html;
    }

    if ((parts = ftpListParseParts(line, flags)) == NULL) {
        const char *p;
        snprintf(html, 8192, "%s\n", line);

        for (p = line; *p && xisspace(*p); p++);
        if (*p && !xisspace(*p))
            flags.listformat_unknown = 1;

        return html;
    }

    if (!strcmp(parts->name, ".") || !strcmp(parts->name, "..")) {
        *html = '\0';
        ftpListPartsFree(&parts);
        return html;
    }

    parts->size += 1023;
    parts->size >>= 10;
    parts->showname = xstrdup(parts->name);

    if (!Config.Ftp.list_wrap) {
        if (strlen(parts->showname) > width - 1) {
            *(parts->showname + width - 1) = '>';
            *(parts->showname + width - 0) = '\0';
        }
    }

    /* {icon} {text} . . . {date}{size}{chdir}{view}{download}{link}\n  */
    xstrncpy(href, rfc1738_escape_part(parts->name), 2048);

    xstrncpy(text, parts->showname, 2048);

    switch (parts->type) {

    case 'd':
        snprintf(icon, 2048, "<IMG border=\"0\" SRC=\"%s\" ALT=\"%-6s\">",
                 mimeGetIconURL("internal-dir"),
                 "[DIR]");
        strcat(href, "/");	/* margin is allocated above */
        break;

    case 'l':
        snprintf(icon, 2048, "<IMG border=\"0\" SRC=\"%s\" ALT=\"%-6s\">",
                 mimeGetIconURL("internal-link"),
                 "[LINK]");
        /* sometimes there is an 'l' flag, but no "->" link */

        if (parts->link) {
            char *link2 = xstrdup(html_quote(rfc1738_escape(parts->link)));
            snprintf(link, 2048, " -> <A HREF=\"%s%s\">%s</A>",
                     *link2 != '/' ? prefix : "", link2,
                     html_quote(parts->link));
            safe_free(link2);
        }

        break;

    case '\0':
        snprintf(icon, 2048, "<IMG border=\"0\" SRC=\"%s\" ALT=\"%-6s\">",
                 mimeGetIconURL(parts->name),
                 "[UNKNOWN]");
        snprintf(chdir, 2048, " <A HREF=\"%s/;type=d\"><IMG border=\"0\" SRC=\"%s\" "
                 "ALT=\"[DIR]\"></A>",
                 rfc1738_escape_part(parts->name),
                 mimeGetIconURL("internal-dir"));
        break;

    case '-':

    default:
        snprintf(icon, 2048, "<IMG border=\"0\" SRC=\"%s\" ALT=\"%-6s\">",
                 mimeGetIconURL(parts->name),
                 "[FILE]");
        snprintf(size, 2048, " %6"PRId64"k", parts->size);
        break;
    }

    if (parts->type != 'd') {
        if (mimeGetViewOption(parts->name)) {
            snprintf(view, 2048, " <A HREF=\"%s%s;type=a\"><IMG border=\"0\" SRC=\"%s\" "
                     "ALT=\"[VIEW]\"></A>",
                     prefix, href, mimeGetIconURL("internal-view"));
        }

        if (mimeGetDownloadOption(parts->name)) {
            snprintf(download, 2048, " <A HREF=\"%s%s;type=i\"><IMG border=\"0\" SRC=\"%s\" "
                     "ALT=\"[DOWNLOAD]\"></A>",
                     prefix, href, mimeGetIconURL("internal-download"));
        }
    }

    /* <A HREF="{href}">{icon}</A> <A HREF="{href}">{text}</A> . . . {date}{size}{chdir}{view}{download}{link}\n  */
    if (parts->type != '\0') {
        snprintf(html, 8192, "<A HREF=\"%s%s\">%s</A> <A HREF=\"%s%s\">%s</A>%s "
                 "%s%8s%s%s%s%s\n",
                 prefix, href, icon, prefix, href, html_quote(text), dots_fill(strlen(text)),
                 parts->date, size, chdir, view, download, link);
    } else {
        /* Plain listing. {icon} {text} ... {chdir}{view}{download} */
        snprintf(html, 8192, "<A HREF=\"%s%s\">%s</A> <A HREF=\"%s%s\">%s</A>%s "
                 "%s%s%s%s\n",
                 prefix, href, icon, prefix, href, html_quote(text), dots_fill(strlen(text)),
                 chdir, view, download, link);
    }

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
    char *t;
    size_t linelen;
    size_t usable;
    StoreEntry *e = entry;
    size_t len = data.readBuf->contentSize();

    if (!len) {
        debugs(9, 3, HERE << "no content to parse for " << e->url()  );
        return;
    }

    /*
     * We need a NULL-terminated buffer for scanning, ick
     */
    sbuf = (char *)xmalloc(len + 1);
    xstrncpy(sbuf, buf, len + 1);
    end = sbuf + len - 1;

    while (*end != '\r' && *end != '\n' && end > sbuf)
        end--;

    usable = end - sbuf;

    debugs(9, 3, HERE << "usable = " << usable);

    if (usable == 0) {
        debugs(9, 3, HERE << "didn't find end for " << e->url()  );
        xfree(sbuf);
        return;
    }

    debugs(9, 3, HERE << (unsigned long int)len << " bytes to play with");

    line = (char *)memAllocate(MEM_4K_BUF);
    end++;
    e->buffer();	/* released when done processing current data payload */
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

        assert(t != NULL);

        writeReplyBody(t, strlen(t));
    }

    data.readBuf->consume(usable);
    memFree(line, MEM_4K_BUF);
    xfree(sbuf);
}

int
FtpStateData::dataDescriptor() const
{
    return data.fd;
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
    scheduleReadControlReply(0);
}

void
FtpStateData::maybeReadVirginBody()
{
    if (data.fd < 0)
        return;

    if (data.read_pending)
        return;

    int read_sz = replyBodySpace(data.readBuf->spaceSize());

    debugs(11,9, HERE << "FTP may read up to " << read_sz << " bytes");

    if (read_sz < 2)	// see http.cc
        return;

    data.read_pending = true;

    typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                      TimeoutDialer(this,&FtpStateData::ftpTimeout));
    commSetTimeout(data.fd, Config.Timeout.read, timeoutCall);

    debugs(9,5,HERE << "queueing read on FD " << data.fd);

    typedef CommCbMemFunT<FtpStateData, CommIoCbParams> Dialer;
    entry->delayAwareRead(data.fd, data.readBuf->space(), read_sz,
                          asyncCall(9, 5, "FtpStateData::dataRead",
                                    Dialer(this, &FtpStateData::dataRead)));
}

void
FtpStateData::dataRead(const CommIoCbParams &io)
{
    int j;
    int bin;

    data.read_pending = false;

    debugs(9, 3, HERE << "ftpDataRead: FD " << io.fd << " Read " << io.size << " bytes");

    if (io.size > 0) {
        kb_incr(&statCounter.server.all.kbytes_in, io.size);
        kb_incr(&statCounter.server.ftp.kbytes_in, io.size);
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    assert(io.fd == data.fd);

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted during dataRead");
        return;
    }

    if (io.flag == COMM_OK && io.size > 0) {
        debugs(9,5,HERE << "appended " << io.size << " bytes to readBuf");
        data.readBuf->appended(io.size);
#if DELAY_POOLS
        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(io.size);
#endif
        IOStats.Ftp.reads++;

        for (j = io.size - 1, bin = 0; j; bin++)
            j >>= 1;

        IOStats.Ftp.read_hist[bin]++;
    }

    if (io.flag != COMM_OK || io.size < 0) {
        debugs(50, ignoreErrno(io.xerrno) ? 3 : DBG_IMPORTANT,
               "ftpDataRead: read error: " << xstrerr(io.xerrno));

        if (ignoreErrno(io.xerrno)) {
            typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
            AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                              TimeoutDialer(this,&FtpStateData::ftpTimeout));
            commSetTimeout(io.fd, Config.Timeout.read, timeoutCall);

            maybeReadVirginBody();
        } else {
            if (!flags.http_header_sent && !fwd->ftpPasvFailed() && flags.pasv_supported) {
                fwd->dontRetry(false);	/* this is a retryable error */
                fwd->ftpPasvFailed(true);
            }

            failed(ERR_READ_ERROR, 0);
            /* failed closes ctrl.fd and frees ftpState */
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

    if (!flags.http_header_sent && data.readBuf->contentSize() >= 0)
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

    if (flags.isdir && !flags.listing_started)
        listingStart();

    if (flags.isdir) {
        parseListing();
    } else
        if (const int csize = data.readBuf->contentSize()) {
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
    const char *auth;

    /* default username */
    xstrncpy(user, "anonymous", MAX_URL);

    /* Check HTTP Authorization: headers (better than defaults, but less than URL) */
    if ( (auth = req_hdr->getAuth(HDR_AUTHORIZATION, "Basic")) ) {
        flags.authenticated = 1;
        loginParser(auth, FTP_LOGIN_NOT_ESCAPED);
    }
    /* we fail with authorization-required error later IFF the FTP server requests it */

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
        }
        else if (!flags.tried_auth_nopass) {
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

    if (request->port != urlDefaultPort(PROTO_FTP)) {
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

    if (request->port != urlDefaultPort(PROTO_FTP)) {
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
    FtpStateData *ftpState = new FtpStateData(fwd);
    ftpState->start();
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
    debugs(9, 5, HERE << "host=" << request->GetHost() << ", path=" <<
           request->urlpath << ", user=" << user << ", passwd=" <<
           password);

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

    for (p = (unsigned const char *)buf, n = 1; *p; n++, p++)
        if (*p == 255)
            n++;

    ret = (char *)xmalloc(n);

    for (p = (unsigned const char *)buf, r=(unsigned char *)ret; *p; p++) {
        *r++ = *p;

        if (*p == 255)
            *r++ = 255;
    }

    *r++ = '\0';
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

    typedef CommCbMemFunT<FtpStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = asyncCall(9, 5, "FtpStateData::ftpWriteCommandCallback",
                                        Dialer(this, &FtpStateData::ftpWriteCommandCallback));
    comm_write(ctrl.fd,
               ctrl.last_command,
               strlen(ctrl.last_command),
               call);

    scheduleReadControlReply(0);
}

void
FtpStateData::ftpWriteCommandCallback(const CommIoCbParams &io)
{

    debugs(9, 5, "ftpWriteCommandCallback: wrote " << io.size << " bytes");

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, FD_WRITE);
        kb_incr(&statCounter.server.all.kbytes_out, io.size);
        kb_incr(&statCounter.server.ftp.kbytes_out, io.size);
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    if (io.flag) {
        debugs(9, DBG_IMPORTANT, "ftpWriteCommandCallback: FD " << io.fd << ": " << xstrerr(io.xerrno));
        failed(ERR_WRITE_ERROR, io.xerrno);
        /* failed closes ctrl.fd and frees ftpState */
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
        end--;

    usable = end - sbuf;

    debugs(9, 3, HERE << "usable = " << usable);

    if (usable == 0) {
        debugs(9, 3, HERE << "didn't find end of line");
        safe_free(sbuf);
        return NULL;
    }

    debugs(9, 3, HERE << len << " bytes to play with");
    end++;
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
    debugs(9, 3, HERE << "FD " << ctrl.fd);

    if (buffered_ok && ctrl.offset > 0) {
        /* We've already read some reply data */
        handleControlReply();
    } else {
        /* XXX What about Config.Timeout.read? */
        typedef CommCbMemFunT<FtpStateData, CommIoCbParams> Dialer;
        AsyncCall::Pointer reader=asyncCall(9, 5, "FtpStateData::ftpReadControlReply",
                                            Dialer(this, &FtpStateData::ftpReadControlReply));
        comm_read(ctrl.fd, ctrl.buf + ctrl.offset, ctrl.size - ctrl.offset, reader);
        /*
         * Cancel the timeout on the Data socket (if any) and
         * establish one on the control socket.
         */

        if (data.fd > -1) {
            AsyncCall::Pointer nullCall =  NULL;
            commSetTimeout(data.fd, -1, nullCall);
        }

        typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                          TimeoutDialer(this,&FtpStateData::ftpTimeout));

        commSetTimeout(ctrl.fd, Config.Timeout.read, timeoutCall);
    }
}

void FtpStateData::ftpReadControlReply(const CommIoCbParams &io)
{
    debugs(9, 3, "ftpReadControlReply: FD " << io.fd << ", Read " << io.size << " bytes");

    if (io.size > 0) {
        kb_incr(&statCounter.server.all.kbytes_in, io.size);
        kb_incr(&statCounter.server.ftp.kbytes_in, io.size);
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

    if (io.flag != COMM_OK || io.size < 0) {
        debugs(50, ignoreErrno(io.xerrno) ? 3 : DBG_IMPORTANT,
               "ftpReadControlReply: read error: " << xstrerr(io.xerrno));

        if (ignoreErrno(io.xerrno)) {
            scheduleReadControlReply(0);
        } else {
            failed(ERR_READ_ERROR, io.xerrno);
            /* failed closes ctrl.fd and frees ftpState */
            return;
        }

        return;
    }

    if (io.size == 0) {
        if (entry->store_status == STORE_PENDING) {
            failed(ERR_FTP_FAILURE, 0);
            /* failed closes ctrl.fd and frees ftpState */
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
        xmemmove(ctrl.buf, ctrl.buf + bytes_used,
                 ctrl.offset);
    }

    /* Move the last line of the reply message to ctrl.last_reply */
    for (W = &ctrl.message; (*W)->next; W = &(*W)->next);
    safe_free(ctrl.last_reply);

    ctrl.last_reply = xstrdup((*W)->key);

    wordlistDestroy(W);

    /* Copy the rest of the message to cwd_message to be printed in
     * error messages
     */
    wordlistAddWl(&cwd_message, ctrl.message);

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
        ftpState->login_att++;

    /* Dont retry if the FTP server accepted the connection */
    ftpState->fwd->dontRetry(true);

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

    if (state == SENT_USER || state == SENT_PASS) {
        if (ctrl.replycode > 500) {
            if (password_url)
                err = errorCon(ERR_FTP_FORBIDDEN, HTTP_FORBIDDEN, fwd->request);
            else
                err = errorCon(ERR_FTP_FORBIDDEN, HTTP_UNAUTHORIZED, fwd->request);
        } else if (ctrl.replycode == 421) {
            err = errorCon(ERR_FTP_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE, fwd->request);
        }
    } else {
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
    errorStateFree(err);
    /* add Authenticate header */
    newrep->header.putAuth("Basic", ftpRealm());

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
        snprintf(cbuf, 1024, "USER %s@%s\r\n",
                 ftpState->user,
                 ftpState->request->GetHost());
    else
        snprintf(cbuf, 1024, "USER %s\r\n", ftpState->user);

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

    snprintf(cbuf, 1024, "PASS %s\r\n", ftpState->password);
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

    snprintf(cbuf, 1024, "TYPE %c\r\n", mode);

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
    debugs(9, 3, HERE);

    if (code == 200) {
        p = path = xstrdup(ftpState->request->urlpath.termedBuf());

        if (*p == '/')
            p++;

        while (*p) {
            d = p;
            p += strcspn(p, "/");

            if (*p)
                *p++ = '\0';

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

    snprintf(cbuf, 1024, "CWD %s\r\n", path);

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

        if (ftpState->cwd_message)
            wordlistDestroy(&ftpState->cwd_message);

        ftpState->cwd_message = ftpState->ctrl.message;

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
    snprintf(cbuf, 1024, "MKD %s\r\n", path);
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
    snprintf(cbuf, 1024, "MDTM %s\r\n", ftpState->filepath);
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
        snprintf(cbuf, 1024, "SIZE %s\r\n", ftpState->filepath);
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
    char h1, h2, h3, h4;
    int n;
    u_short port;
    IpAddress ipa_remote;
    int fd = ftpState->data.fd;
    char *buf;
    debugs(9, 3, HERE);

    if (code != 229 && code != 522) {
        if (code == 200) {
            /* handle broken servers (RFC 2428 says OK code for EPSV MUST be 229 not 200) */
            /* vsftpd for one send '200 EPSV ALL ok.' without even port info.
             * Its okay to re-send EPSV 1/2 but nothing else. */
            debugs(9, DBG_IMPORTANT, "Broken FTP Server at " << fd_table[ftpState->ctrl.fd].ipaddr << ". Wrong accept code for EPSV");
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
        /* TODO: handle the (1,2) case. We might get it back after EPSV ALL 
         * which means close data + control without self-destructing and re-open from scratch. */
        debugs(9, 5, HERE << "scanning: " << ftpState->ctrl.last_reply);
        buf = ftpState->ctrl.last_reply;
        while (buf != NULL && *buf != '\0' && *buf != '\n' && *buf != '(') ++buf;
        if (buf != NULL && *buf == '\n') ++buf;

        if (buf == NULL || *buf == '\0') {
            /* handle broken server (RFC 2428 says MUST specify supported protocols in 522) */
            debugs(9, DBG_IMPORTANT, "Broken FTP Server at " << fd_table[ftpState->ctrl.fd].ipaddr << ". 522 error missing protocol negotiation hints");
            ftpSendPassive(ftpState);
        } else if (strcmp(buf, "(1)") == 0) {
            ftpState->state = SENT_EPSV_2; /* simulate having sent and failed EPSV 2 */
            ftpSendPassive(ftpState);
        } else if (strcmp(buf, "(2)") == 0) {
#if USE_IPV6
            /* If server only supports EPSV 2 and we have already tried that. Go straight to EPRT */
            if (ftpState->state == SENT_EPSV_2) {
                ftpSendEPRT(ftpState);
            } else {
                /* or try the next Passive mode down the chain. */
                ftpSendPassive(ftpState);
            }
#else
            /* We do not support IPv6. Remote server requires it.
               So we must simulate having failed all EPSV methods. */
            ftpState->state = SENT_EPSV_1;
            ftpSendPassive(ftpState);
#endif
        }
        else {
            /* handle broken server (RFC 2428 says MUST specify supported protocols in 522) */
            debugs(9, DBG_IMPORTANT, "WARNING: Server at " << fd_table[ftpState->ctrl.fd].ipaddr << " sent unknown protocol negotiation hint: " << buf);
            ftpSendPassive(ftpState);
        }
        return;
    }

    /*  229 Entering Extended Passive Mode (|||port|) */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debugs(9, 5, "scanning: " << ftpState->ctrl.last_reply);

    buf = ftpState->ctrl.last_reply + strcspn(ftpState->ctrl.last_reply, "(");

    n = sscanf(buf, "(%c%c%c%hu%c)", &h1, &h2, &h3, &port, &h4);

    if (h1 != h2 || h1 != h3 || h1 != h4) {
        debugs(9, DBG_IMPORTANT, "Invalid EPSV reply from " <<
               fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendPassive(ftpState);
        return;
    }

    if (0 == port) {
        debugs(9, DBG_IMPORTANT, "Unsafe EPSV reply from " <<
               fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendPassive(ftpState);
        return;
    }

    if (Config.Ftp.sanitycheck) {
        if (port < 1024) {
            debugs(9, DBG_IMPORTANT, "Unsafe EPSV reply from " <<
                   fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
                   ftpState->ctrl.last_reply);

            ftpSendPassive(ftpState);
            return;
        }
    }

    ftpState->data.port = port;

    ftpState->data.host = xstrdup(fd_table[ftpState->ctrl.fd].ipaddr);

    safe_free(ftpState->ctrl.last_command);

    safe_free(ftpState->ctrl.last_reply);

    ftpState->ctrl.last_command = xstrdup("Connect to server data port");

    debugs(9, 3, HERE << "connecting to " << ftpState->data.host << ", port " << ftpState->data.port);

    commConnectStart(fd, ftpState->data.host, port, FtpStateData::ftpPasvCallback, ftpState);
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
    IpAddress addr;
    struct addrinfo *AI = NULL;

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
      * Locates the Address of the remote server. */
    addr.InitAddrInfo(AI);

    if (getsockname(ftpState->ctrl.fd, AI->ai_addr, &AI->ai_addrlen)) {
        /** If it cannot be located the FTP Session is killed. */
        addr.FreeAddrInfo(AI);
        debugs(9, DBG_CRITICAL, HERE << "getsockname(" << ftpState->ctrl.fd << ",'" << addr << "',...): " << xstrerror());
        ftpFail(ftpState);
        return;
    }

    addr = *AI;

    addr.FreeAddrInfo(AI);

    /** Otherwise, Open data channel with the same local address as control channel (on a new random port!) */
    addr.SetPort(0);
    int fd = comm_open(SOCK_STREAM,
                       IPPROTO_TCP,
                       addr,
                       COMM_NONBLOCKING,
                       ftpState->entry->url());

    debugs(9, 3, HERE << "Unconnected data socket created on FD " << fd << " to " << addr);

    if (fd < 0) {
        ftpFail(ftpState);
        return;
    }

    ftpState->data.opened(fd, ftpState->dataCloser());

    /** \par
      * Send EPSV (ALL,2,1) or PASV on the control channel.
      *
      *  - EPSV ALL  is used if enabled.
      *  - EPSV 2    is used if ALL is disabled and IPv6 is available.
      *  - EPSV 1    is used if EPSV 2 (IPv6) fails or is not available.
      *  - PASV      is used if EPSV 1 fails.
      */
    switch (ftpState->state) {
    case SENT_EPSV_1: /* EPSV options exhausted. Try PASV now. */
        snprintf(cbuf, 1024, "PASV\r\n");
        ftpState->state = SENT_PASV;
        break;

    case SENT_EPSV_2: /* EPSV IPv6 failed. Try EPSV IPv4 */
        snprintf(cbuf, 1024, "EPSV 1\r\n");
        ftpState->state = SENT_EPSV_1;
        break;

    case SENT_EPSV_ALL: /* EPSV ALL resulted in a bad response. Try ther EPSV methods. */
        ftpState->flags.epsv_all_sent = true;
        snprintf(cbuf, 1024, "EPSV 2\r\n");
        ftpState->state = SENT_EPSV_2;
        break;

    default:
        if (!Config.Ftp.epsv) {
            snprintf(cbuf, 1024, "PASV\r\n");
            ftpState->state = SENT_PASV;
        } else if (Config.Ftp.epsv_all) {
            snprintf(cbuf, 1024, "EPSV ALL\r\n");
            ftpState->state = SENT_EPSV_ALL;
            /* block other non-EPSV connections being attempted */
            ftpState->flags.epsv_all_sent = true;
        } else {
#if USE_IPV6
            snprintf(cbuf, 1024, "EPSV 2\r\n");
            ftpState->state = SENT_EPSV_2;
#else
            snprintf(cbuf, 1024, "EPSV 1\r\n");
            ftpState->state = SENT_EPSV_1;
#endif
        }
        break;
    }

    ftpState->writeCommand(cbuf);

    /*
     * ugly hack for ftp servers like ftp.netscape.com that sometimes
     * dont acknowledge PASV commands.
     */
    typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                      TimeoutDialer(ftpState,&FtpStateData::ftpTimeout));

    commSetTimeout(ftpState->data.fd, 15, timeoutCall);
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
    u_short port;
    IpAddress ipa_remote;
    int fd = ftpState->data.fd;
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
               fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendEPRT(ftpState);
        return;
    }

    snprintf(ipaddr, 1024, "%d.%d.%d.%d", h1, h2, h3, h4);

    ipa_remote = ipaddr;

    if ( ipa_remote.IsAnyAddr() ) {
        debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
               fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendEPRT(ftpState);
        return;
    }

    port = ((p1 << 8) + p2);

    if (0 == port) {
        debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
               fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
               ftpState->ctrl.last_reply);

        ftpSendEPRT(ftpState);
        return;
    }

    if (Config.Ftp.sanitycheck) {
        if (port < 1024) {
            debugs(9, DBG_IMPORTANT, "Unsafe PASV reply from " <<
                   fd_table[ftpState->ctrl.fd].ipaddr << ": " <<
                   ftpState->ctrl.last_reply);

            ftpSendEPRT(ftpState);
            return;
        }
    }

    ftpState->data.port = port;

    if (Config.Ftp.sanitycheck)
        ftpState->data.host = xstrdup(fd_table[ftpState->ctrl.fd].ipaddr);
    else
        ftpState->data.host = xstrdup(ipaddr);

    safe_free(ftpState->ctrl.last_command);

    safe_free(ftpState->ctrl.last_reply);

    ftpState->ctrl.last_command = xstrdup("Connect to server data port");

    debugs(9, 3, HERE << "connecting to " << ftpState->data.host << ", port " << ftpState->data.port);

    commConnectStart(fd, ipaddr, port, FtpStateData::ftpPasvCallback, ftpState);
}

void
FtpStateData::ftpPasvCallback(int fd, const DnsLookupDetails &dns, comm_err_t status, int xerrno, void *data)
{
    FtpStateData *ftpState = (FtpStateData *)data;
    debugs(9, 3, HERE);
    ftpState->request->recordLookup(dns);

    if (status != COMM_OK) {
        debugs(9, 2, HERE << "Failed to connect. Retrying without PASV.");
        ftpState->fwd->dontRetry(false);	/* this is a retryable error */
        ftpState->fwd->ftpPasvFailed(true);
        ftpState->failed(ERR_NONE, 0);
        /* failed closes ctrl.fd and frees ftpState */
        return;
    }

    ftpRestOrList(ftpState);
}

/// \ingroup ServerProtocolFTPInternal
static int
ftpOpenListenSocket(FtpStateData * ftpState, int fallback)
{
    int fd;

    IpAddress addr;
    struct addrinfo *AI = NULL;
    int on = 1;
    int x = 0;

    /// Close old data channel, if any. We may open a new one below.
    ftpState->data.close();

    /*
     * Set up a listen socket on the same local address as the
     * control connection.
     */

    addr.InitAddrInfo(AI);

    x = getsockname(ftpState->ctrl.fd, AI->ai_addr, &AI->ai_addrlen);

    addr = *AI;

    addr.FreeAddrInfo(AI);

    if (x) {
        debugs(9, DBG_CRITICAL, HERE << "getsockname(" << ftpState->ctrl.fd << ",..): " << xstrerror());
        return -1;
    }

    /*
     * REUSEADDR is needed in fallback mode, since the same port is
     * used for both control and data.
     */
    if (fallback) {
        setsockopt(ftpState->ctrl.fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
    } else {
        /* if not running in fallback mode a new port needs to be retrieved */
        addr.SetPort(0);
    }

    fd = comm_open(SOCK_STREAM,
                   IPPROTO_TCP,
                   addr,
                   COMM_NONBLOCKING | (fallback ? COMM_REUSEADDR : 0),
                   ftpState->entry->url());
    debugs(9, 3, HERE << "Unconnected data socket created on FD " << fd  );

    if (fd < 0) {
        debugs(9, DBG_CRITICAL, HERE << "comm_open failed");
        return -1;
    }

    if (comm_listen(fd) < 0) {
        comm_close(fd);
        return -1;
    }

    ftpState->data.opened(fd, ftpState->dataCloser());
    ftpState->data.port = comm_local_port(fd);
    ftpState->data.host = NULL;
    return fd;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendPORT(FtpStateData * ftpState)
{
    int fd;

    IpAddress ipa;
    struct addrinfo *AI = NULL;
    unsigned char *addrptr;
    unsigned char *portptr;

    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendPort"))
        return;

    if (Config.Ftp.epsv_all && ftpState->flags.epsv_all_sent) {
        debugs(9, DBG_IMPORTANT, "FTP does not allow PORT method after 'EPSV ALL' has been sent.");
        return;
    }

    debugs(9, 3, HERE);
    ftpState->flags.pasv_supported = 0;
    fd = ftpOpenListenSocket(ftpState, 0);
    ipa.InitAddrInfo(AI);

    if (getsockname(fd, AI->ai_addr, &AI->ai_addrlen)) {
        ipa.FreeAddrInfo(AI);
        debugs(9, DBG_CRITICAL, HERE << "getsockname(" << fd << ",..): " << xstrerror());

        /* XXX Need to set error message */
        ftpFail(ftpState);
        return;
    }

#if USE_IPV6
    if ( AI->ai_addrlen != sizeof(struct sockaddr_in) ) {
        ipa.FreeAddrInfo(AI);
        /* IPv6 CANNOT send PORT command.                           */
        /* we got here by attempting and failing an EPRT            */
        /* using the same reply code should simulate a PORT failure */
        ftpReadPORT(ftpState);
        return;
    }
#endif

    addrptr = (unsigned char *) &((struct sockaddr_in*)AI->ai_addr)->sin_addr;
    portptr = (unsigned char *) &((struct sockaddr_in*)AI->ai_addr)->sin_port;
    snprintf(cbuf, 1024, "PORT %d,%d,%d,%d,%d,%d\r\n",
             addrptr[0], addrptr[1], addrptr[2], addrptr[3],
             portptr[0], portptr[1]);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_PORT;

    ipa.FreeAddrInfo(AI);
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
    int fd;
    IpAddress addr;
    struct addrinfo *AI = NULL;
    char buf[MAX_IPSTRLEN];

    if (Config.Ftp.epsv_all && ftpState->flags.epsv_all_sent) {
        debugs(9, DBG_IMPORTANT, "FTP does not allow EPRT method after 'EPSV ALL' has been sent.");
        return;
    }

    debugs(9, 3, HERE);
    ftpState->flags.pasv_supported = 0;
    fd = ftpOpenListenSocket(ftpState, 0);

    addr.InitAddrInfo(AI);

    if (getsockname(fd, AI->ai_addr, &AI->ai_addrlen)) {
        addr.FreeAddrInfo(AI);
        debugs(9, DBG_CRITICAL, HERE << "getsockname(" << fd << ",..): " << xstrerror());

        /* XXX Need to set error message */
        ftpFail(ftpState);
        return;
    }

    addr = *AI;

    /* RFC 2428 defines EPRT as IPv6 equivalent to IPv4 PORT command. */
    /* Which can be used by EITHER protocol. */
    snprintf(cbuf, 1024, "EPRT |%d|%s|%d|\r\n",
             ( addr.IsIPv6() ? 2 : 1 ),
             addr.NtoA(buf,MAX_IPSTRLEN),
             addr.GetPort() );

    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_EPRT;

    addr.FreeAddrInfo(AI);
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
void FtpStateData::ftpAcceptDataConnection(const CommAcceptCbParams &io)
{
    char ntoapeer[MAX_IPSTRLEN];
    debugs(9, 3, "ftpAcceptDataConnection");

    if (io.flag == COMM_ERR_CLOSING)
        return;

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("entry aborted when accepting data conn");
        return;
    }

    /** \par
     * When squid.conf ftp_sanitycheck is enabled, check the new connection is actually being
     * made by the remote client which is connected to the FTP control socket.
     * This prevents third-party hacks, but also third-party load balancing handshakes.
     */
    if (Config.Ftp.sanitycheck) {
        io.details.peer.NtoA(ntoapeer,MAX_IPSTRLEN);

        if (strcmp(fd_table[ctrl.fd].ipaddr, ntoapeer) != 0) {
            debugs(9, DBG_IMPORTANT,
                   "FTP data connection from unexpected server (" <<
                   io.details.peer << "), expecting " <<
                   fd_table[ctrl.fd].ipaddr);

            comm_close(io.nfd);
            typedef CommCbMemFunT<FtpStateData, CommAcceptCbParams> acceptDialer;
            AsyncCall::Pointer acceptCall = asyncCall(11, 5, "FtpStateData::ftpAcceptDataConnection",
                                            acceptDialer(this, &FtpStateData::ftpAcceptDataConnection));
            comm_accept(data.fd, acceptCall);
            return;
        }
    }

    if (io.flag != COMM_OK) {
        debugs(9, DBG_IMPORTANT, "ftpHandleDataAccept: comm_accept(" << io.nfd << "): " << xstrerr(io.xerrno));
        /** \todo XXX Need to set error message */
        ftpFail(this);
        return;
    }

    /**\par
     * Replace the Listen socket with the accepted data socket */
    data.close();
    data.opened(io.nfd, dataCloser());
    data.port = io.details.peer.GetPort();
    io.details.peer.NtoA(data.host,SQUIDHOSTNAMELEN);

    debugs(9, 3, "ftpAcceptDataConnection: Connected data socket on " <<
           "FD " << io.nfd << " to " << io.details.peer << " FD table says: " <<
           "ctrl-peer= " << fd_table[ctrl.fd].ipaddr << ", " <<
           "data-peer= " << fd_table[data.fd].ipaddr);


    AsyncCall::Pointer nullCall = NULL;
    commSetTimeout(ctrl.fd, -1, nullCall);

    typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                      TimeoutDialer(this,&FtpStateData::ftpTimeout));
    commSetTimeout(data.fd, Config.Timeout.read, timeoutCall);

    /*\todo XXX We should have a flag to track connect state...
     *    host NULL -> not connected, port == local port
     *    host set  -> connected, port == remote port
     */
    /* Restart state (SENT_NLST/LIST/RETR) */
    FTP_SM_FUNCS[state] (this);
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
        snprintf(cbuf, 1024, "STOR %s\r\n", ftpState->filepath);
        ftpState->writeCommand(cbuf);
        ftpState->state = SENT_STOR;
    } else if (ftpState->request->header.getInt64(HDR_CONTENT_LENGTH) > 0) {
        /* File upload without a filename. use STOU to generate one */
        snprintf(cbuf, 1024, "STOU\r\n");
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

    if (code == 125 || (code == 150 && data.host)) {
        if (!startRequestBodyFlow()) { // register to receive body data
            ftpFail(this);
            return;
        }

        /*\par
         * When client status is 125, or 150 without a hostname, Begin data transfer. */
        debugs(9, 3, HERE << "starting data transfer");
        sendMoreRequestBody();
        /** \par
         * Cancel the timeout on the Control socket and
         * establish one on the data socket.
         */
        AsyncCall::Pointer nullCall = NULL;
        commSetTimeout(ctrl.fd, -1, nullCall);

        typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                          TimeoutDialer(this,&FtpStateData::ftpTimeout));

        commSetTimeout(data.fd, Config.Timeout.read, timeoutCall);

        state = WRITING_DATA;
        debugs(9, 3, HERE << "writing data channel");
    } else if (code == 150) {
        /*\par
         * When client code is 150 with a hostname, Accept data channel. */
        debugs(9, 3, "ftpReadStor: accepting data channel");
        typedef CommCbMemFunT<FtpStateData, CommAcceptCbParams> acceptDialer;
        AsyncCall::Pointer acceptCall = asyncCall(11, 5, "FtpStateData::ftpAcceptDataConnection",
                                        acceptDialer(this, &FtpStateData::ftpAcceptDataConnection));

        comm_accept(data.fd, acceptCall);
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

    snprintf(cbuf, 1024, "REST %"PRId64"\r\n", ftpState->restart_offset);
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
        snprintf(cbuf, 1024, "LIST %s\r\n", ftpState->filepath);
    } else {
        snprintf(cbuf, 1024, "LIST\r\n");
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
        snprintf(cbuf, 1024, "NLST %s\r\n", ftpState->filepath);
    } else {
        snprintf(cbuf, 1024, "NLST\r\n");
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

    if (code == 125 || (code == 150 && ftpState->data.host)) {
        /* Begin data transfer */
        /* XXX what about Config.Timeout.read? */
        ftpState->maybeReadVirginBody();
        ftpState->state = READING_DATA;
        /*
         * Cancel the timeout on the Control socket and establish one
         * on the data socket
         */
        AsyncCall::Pointer nullCall = NULL;
        commSetTimeout(ftpState->ctrl.fd, -1, nullCall);
        return;
    } else if (code == 150) {
        /* Accept data channel */
        typedef CommCbMemFunT<FtpStateData, CommAcceptCbParams> acceptDialer;
        AsyncCall::Pointer acceptCall = asyncCall(11, 5, "FtpStateData::ftpAcceptDataConnection",
                                        acceptDialer(ftpState, &FtpStateData::ftpAcceptDataConnection));

        comm_accept(ftpState->data.fd, acceptCall);
        /*
         * Cancel the timeout on the Control socket and establish one
         * on the data socket
         */
        AsyncCall::Pointer nullCall = NULL;
        commSetTimeout(ftpState->ctrl.fd, -1, nullCall);

        typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                          TimeoutDialer(ftpState,&FtpStateData::ftpTimeout));
        commSetTimeout(ftpState->data.fd, Config.Timeout.read, timeoutCall);
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
    snprintf(cbuf, 1024, "RETR %s\r\n", ftpState->filepath);
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_RETR;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadRetr(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && ftpState->data.host)) {
        /* Begin data transfer */
        debugs(9, 3, HERE << "reading data channel");
        /* XXX what about Config.Timeout.read? */
        ftpState->maybeReadVirginBody();
        ftpState->state = READING_DATA;
        /*
         * Cancel the timeout on the Control socket and establish one
         * on the data socket
         */
        AsyncCall::Pointer nullCall = NULL;
        commSetTimeout(ftpState->ctrl.fd, -1, nullCall);
    } else if (code == 150) {
        /* Accept data channel */
        typedef CommCbMemFunT<FtpStateData, CommAcceptCbParams> acceptDialer;
        AsyncCall::Pointer acceptCall = asyncCall(11, 5, "FtpStateData::ftpAcceptDataConnection",
                                        acceptDialer(ftpState, &FtpStateData::ftpAcceptDataConnection));
        comm_accept(ftpState->data.fd, acceptCall);
        /*
         * Cancel the timeout on the Control socket and establish one
         * on the data socket
         */
        AsyncCall::Pointer nullCall = NULL;
        commSetTimeout(ftpState->ctrl.fd, -1, nullCall);

        typedef CommCbMemFunT<FtpStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall =  asyncCall(9, 5, "FtpStateData::ftpTimeout",
                                          TimeoutDialer(ftpState,&FtpStateData::ftpTimeout));
        commSetTimeout(ftpState->data.fd, Config.Timeout.read, timeoutCall);
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

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadTransferDone(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 226 || code == 250) {
        /* Connection closed; retrieval done. */

        if (ftpState->flags.html_header_sent)
            ftpState->listingFinish();

        ftpSendQuit(ftpState);
    } else {			/* != 226 */
        debugs(9, DBG_IMPORTANT, HERE << "Got code " << code << " after reading data");
        ftpState->failed(ERR_FTP_FAILURE, 0);
        /* failed closes ctrl.fd and frees ftpState */
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
        kb_incr(&statCounter.server.ftp.kbytes_out, io.size);
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

    snprintf(cbuf, 1024, "QUIT\r\n");
    ftpState->writeCommand(cbuf);
    ftpState->state = SENT_QUIT;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadQuit(FtpStateData * ftpState)
{
    /** \todo XXX should this just be a case of abortTransaction? */
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
    /* failed() closes ctrl.fd and frees this */
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
    ErrorState *err;
    const char *command, *reply;
    /* Translate FTP errors into HTTP errors */
    err = NULL;

    switch (error) {

    case ERR_NONE:

        switch (state) {

        case SENT_USER:

        case SENT_PASS:

            if (ctrl.replycode > 500)
                if (password_url)
                    err = errorCon(ERR_FTP_FORBIDDEN, HTTP_FORBIDDEN, fwd->request);
                else
                    err = errorCon(ERR_FTP_FORBIDDEN, HTTP_UNAUTHORIZED, fwd->request);

            else if (ctrl.replycode == 421)
                err = errorCon(ERR_FTP_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE, fwd->request);

            break;

        case SENT_CWD:

        case SENT_RETR:
            if (ctrl.replycode == 550)
                err = errorCon(ERR_FTP_NOT_FOUND, HTTP_NOT_FOUND, fwd->request);

            break;

        default:
            break;
        }

        break;

    case ERR_READ_TIMEOUT:
        err = errorCon(error, HTTP_GATEWAY_TIMEOUT, fwd->request);
        break;

    default:
        err = errorCon(error, HTTP_BAD_GATEWAY, fwd->request);
        break;
    }

    if (err == NULL)
        err = errorCon(ERR_FTP_FAILURE, HTTP_BAD_GATEWAY, fwd->request);

    err->xerrno = xerrno;

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

    fwd->fail(err);
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendReply(FtpStateData * ftpState)
{
    ErrorState *err;
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

    err = errorCon(err_code, http_code, ftpState->request);

    if (ftpState->old_request)
        err->ftp.request = xstrdup(ftpState->old_request);
    else
        err->ftp.request = xstrdup(ftpState->ctrl.last_command);

    if (ftpState->old_reply)
        err->ftp.reply = xstrdup(ftpState->old_reply);
    else if (ftpState->ctrl.last_reply)
        err->ftp.reply = xstrdup(ftpState->ctrl.last_reply);
    else
        err->ftp.reply = xstrdup("");

    errorAppendEntry(ftpState->entry, err);

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
    StoreEntry *e = entry;

    debugs(9, 3, HERE);

    if (flags.http_header_sent)
        return;

    HttpReply *reply = new HttpReply;

    flags.http_header_sent = 1;

    assert(e->isEmpty());

    EBIT_CLR(e->flags, ENTRY_FWD_HDR_WAIT);

    e->buffer();	/* released when done processing current data payload */

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

    HttpVersion version(1, 0);
    if (0 == getCurrentOffset()) {
        /* Full reply */
        reply->setHeaders(version, HTTP_OK, "Gatewaying",
                          mime_type, theSize, mdtm, -2);
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
        reply->setHeaders(version, HTTP_OK, "Gatewaying",
                          mime_type, theSize, mdtm, -2);
    } else {
        /* Partial reply */
        HttpHdrRangeSpec range_spec;
        range_spec.offset = getCurrentOffset();
        range_spec.length = theSize - getCurrentOffset();
        reply->setHeaders(version, HTTP_PARTIAL_CONTENT, "Gatewaying",
                          mime_type, theSize - getCurrentOffset(), mdtm, -2);
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
    ErrorState *err = errorCon(ERR_CACHE_ACCESS_DENIED, HTTP_UNAUTHORIZED, request);
    HttpReply *newrep = err->BuildHttpReply();
    errorStateFree(err);
    /* add Authenticate header */
    newrep->header.putAuth("Basic", realm);
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

    if (request->protocol != PROTO_FTP)
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
}

/**
 * Call this when there is data from the origin server
 * which should be sent to either StoreEntry, or to ICAP...
 */
void
FtpStateData::writeReplyBody(const char *data, size_t len)
{
    debugs(9, 5, HERE << "writing " << len << " bytes to the reply");
    addVirginReplyBody(data, len);
}

/**
 * called after we wrote the last byte of the request body
 */
void
FtpStateData::doneSendingRequestBody()
{
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
               "double-complete on FD " << ctrl.fd << ", Data FD " << data.fd <<
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
    debugs(9,3, HERE << "closing FTP server FD " << ctrl.fd << ", Data FD " << data.fd << ", this " << this);

    if (ctrl.fd > -1) {
        fwd->unregister(ctrl.fd);
        ctrl.close();
    }

    data.close();
}

/**
 * Did we close all FTP server connection(s)?
 *
 \retval true	Both server control and data channels are closed.
 \retval false	Either control channel or data is still active.
 */
bool
FtpStateData::doneWithServer() const
{
    return ctrl.fd < 0 && data.fd < 0;
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
    if (ctrl.fd < 0) {
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
           "; FD " << ctrl.fd << ", Data FD " << data.fd << ", this " << this);
    if (ctrl.fd >= 0) {
        comm_close(ctrl.fd);
        return;
    }

    fwd->handleUnregisteredServerEnd();
    deleteThis("FtpStateData::abortTransaction");
}

/// creates a data channel Comm close callback
AsyncCall::Pointer
FtpStateData::dataCloser()
{
    typedef CommCbMemFunT<FtpStateData, CommCloseCbParams> Dialer;
    return asyncCall(9, 5, "FtpStateData::dataClosed",
                     Dialer(this, &FtpStateData::dataClosed));
}

/// configures the channel with a descriptor and registers a close handler
void
FtpChannel::opened(int aFd, const AsyncCall::Pointer &aCloser)
{
    assert(fd < 0);
    assert(closer == NULL);

    assert(aFd >= 0);
    assert(aCloser != NULL);

    fd = aFd;
    closer = aCloser;
    comm_add_close_handler(fd, closer);
}

/// planned close: removes the close handler and calls comm_close
void
FtpChannel::close()
{
    if (fd >= 0) {
        comm_remove_close_handler(fd, closer);
        closer = NULL;
        comm_close(fd); // we do not expect to be called back
        fd = -1;
    }
}

/// just resets fd and close handler
void
FtpChannel::clear()
{
    fd = -1;
    closer = NULL;
}
