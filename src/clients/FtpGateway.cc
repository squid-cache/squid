/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 09    File Transfer Protocol (FTP) */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "clients/forward.h"
#include "clients/FtpClient.h"
#include "comm.h"
#include "comm/ConnOpener.h"
#include "comm/Read.h"
#include "comm/TcpAcceptor.h"
#include "CommCalls.h"
#include "compat/strtoll.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "FwdState.h"
#include "html_quote.h"
#include "HttpHdrContRange.h"
#include "HttpHeader.h"
#include "HttpHeaderRange.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "mime.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "tools.h"
#include "URL.h"
#include "util.h"
#include "wordlist.h"

#if USE_DELAY_POOLS
#include "DelayPools.h"
#include "MemObject.h"
#endif

#include <cerrno>

namespace Ftp
{

struct GatewayFlags {

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

class Gateway;
typedef void (StateMethod)(Ftp::Gateway *);

/// FTP Gateway: An FTP client that takes an HTTP request with an ftp:// URI,
/// converts it into one or more FTP commands, and then
/// converts one or more FTP responses into the final HTTP response.
class Gateway : public Ftp::Client
{
    CBDATA_CLASS(Gateway);

public:
    Gateway(FwdState *);
    virtual ~Gateway();
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
    time_t mdtm;
    int64_t theSize;
    wordlist *pathcomps;
    char *filepath;
    char *dirpath;
    int64_t restart_offset;
    char *proxy_host;
    size_t list_width;
    String cwd_message;
    char *old_filepath;
    char typecode;
    MemBuf listing;     ///< FTP directory listing in HTML format.

    GatewayFlags flags;

public:
    // these should all be private
    virtual void start();
    virtual Http::StatusCode failedHttpStatus(err_type &error);
    int restartable();
    void appendSuccessHeader();
    void hackShortcut(StateMethod *nextState);
    void unhack();
    void readStor();
    void parseListing();
    MemBuf *htmlifyListEntry(const char *line);
    void completedListing(void);

    /// create a data channel acceptor and start listening.
    void listenForDataChannel(const Comm::ConnectionPointer &conn);

    int checkAuth(const HttpHeader * req_hdr);
    void checkUrlpath();
    void buildTitleUrl();
    void writeReplyBody(const char *, size_t len);
    void printfReplyBody(const char *fmt, ...);
    virtual void completeForwarding();
    void processHeadResponse();
    void processReplyBody();
    void setCurrentOffset(int64_t offset) { currentOffset = offset; }
    int64_t getCurrentOffset() const { return currentOffset; }

    virtual void dataChannelConnected(const CommConnectCbParams &io);
    static PF ftpDataWrite;
    virtual void timeout(const CommTimeoutCbParams &io);
    void ftpAcceptDataConnection(const CommAcceptCbParams &io);

    static HttpReply *ftpAuthRequired(HttpRequest * request, SBuf &realm);
    SBuf ftpRealm();
    void loginFailed(void);

    virtual void haveParsedReplyHeaders();

    virtual bool haveControlChannel(const char *caller_name) const;

protected:
    virtual void handleControlReply();
    virtual void dataClosed(const CommCloseCbParams &io);

private:
    virtual bool mayReadVirginReplyBody() const;
    // BodyConsumer for HTTP: consume request body.
    virtual void handleRequestBodyProducerAborted();

    void loginParser(const SBuf &login, bool escaped);
};

} // namespace Ftp

typedef Ftp::StateMethod FTPSM; // to avoid lots of non-changes

CBDATA_NAMESPACED_CLASS_INIT(Ftp, Gateway);

typedef struct {
    char type;
    int64_t size;
    char *date;
    char *name;
    char *showname;
    char *link;
} ftpListParts;

#define CTRL_BUFLEN 16*1024
static char cbuf[CTRL_BUFLEN];

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
#if 0
static FTPSM ftpSendEPRT;
#endif
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
0   CRITICAL Events
1   IMPORTANT Events
    Protocol and Transmission failures.
2   FTP Protocol Chatter
3   Logic Flows
4   Data Parsing Flows
5   Data Dumps
7   ??
************************************************/

/************************************************
** State Machine Description (excluding hacks) **
*************************************************
From            To
---------------------------------------
Welcome         User
User            Pass
Pass            Type
Type            TraverseDirectory / GetFile
TraverseDirectory   Cwd / GetFile / ListDir
Cwd         TraverseDirectory / Mkdir
GetFile         Mdtm
Mdtm            Size
Size            Epsv
ListDir         Epsv
Epsv            FileOrList
FileOrList      Rest / Retr / Nlst / List / Mkdir (PUT /xxx;type=d)
Rest            Retr
Retr / Nlst / List  DataRead* (on datachannel)
DataRead*       ReadTransferDone
ReadTransferDone    DataTransferDone
Stor            DataWrite* (on datachannel)
DataWrite*      RequestPutBody** (from client)
RequestPutBody**    DataWrite* / WriteTransferDone
WriteTransferDone   DataTransferDone
DataTransferDone    Quit
Quit            -
************************************************/

FTPSM *FTP_SM_FUNCS[] = {
    ftpReadWelcome,     /* BEGIN */
    ftpReadUser,        /* SENT_USER */
    ftpReadPass,        /* SENT_PASS */
    ftpReadType,        /* SENT_TYPE */
    ftpReadMdtm,        /* SENT_MDTM */
    ftpReadSize,        /* SENT_SIZE */
    ftpReadEPRT,        /* SENT_EPRT */
    ftpReadPORT,        /* SENT_PORT */
    ftpReadEPSV,        /* SENT_EPSV_ALL */
    ftpReadEPSV,        /* SENT_EPSV_1 */
    ftpReadEPSV,        /* SENT_EPSV_2 */
    ftpReadPasv,        /* SENT_PASV */
    ftpReadCwd,     /* SENT_CWD */
    ftpReadList,        /* SENT_LIST */
    ftpReadList,        /* SENT_NLST */
    ftpReadRest,        /* SENT_REST */
    ftpReadRetr,        /* SENT_RETR */
    ftpReadStor,        /* SENT_STOR */
    ftpReadQuit,        /* SENT_QUIT */
    ftpReadTransferDone,    /* READING_DATA (RETR,LIST,NLST) */
    ftpWriteTransferDone,   /* WRITING_DATA (STOR) */
    ftpReadMkdir,       /* SENT_MKDIR */
    NULL,           /* SENT_FEAT */
    NULL,           /* SENT_PWD */
    NULL,           /* SENT_CDUP*/
    NULL,           /* SENT_DATA_REQUEST */
    NULL            /* SENT_COMMAND */
};

/// handler called by Comm when FTP data channel is closed unexpectedly
void
Ftp::Gateway::dataClosed(const CommCloseCbParams &io)
{
    Ftp::Client::dataClosed(io);
    failed(ERR_FTP_FAILURE, 0);
    /* failed closes ctrl.conn and frees ftpState */

    /* NP: failure recovery may be possible when its only a data.conn failure.
     *     if the ctrl.conn is still fine, we can send ABOR down it and retry.
     *     Just need to watch out for wider Squid states like shutting down or reconfigure.
     */
}

Ftp::Gateway::Gateway(FwdState *fwdState):
    AsyncJob("FtpStateData"),
    Ftp::Client(fwdState),
    password_url(0),
    reply_hdr(NULL),
    reply_hdr_state(0),
    conn_att(0),
    login_att(0),
    mdtm(-1),
    theSize(-1),
    pathcomps(NULL),
    filepath(NULL),
    dirpath(NULL),
    restart_offset(0),
    proxy_host(NULL),
    list_width(0),
    old_filepath(NULL),
    typecode('\0')
{
    debugs(9, 3, entry->url());

    *user = 0;
    *password = 0;
    memset(&flags, 0, sizeof(flags));

    if (Config.Ftp.passive && !flags.pasv_failed)
        flags.pasv_supported = 1;

    flags.rest_supported = 1;

    if (request->method == Http::METHOD_PUT)
        flags.put = 1;

    initReadBuf();
}

Ftp::Gateway::~Gateway()
{
    debugs(9, 3, entry->url());

    if (Comm::IsConnOpen(ctrl.conn)) {
        debugs(9, DBG_IMPORTANT, "Internal bug: FTP Gateway left open " <<
               "control channel " << ctrl.conn);
    }

    if (reply_hdr) {
        memFree(reply_hdr, MEM_8K_BUF);
        reply_hdr = NULL;
    }

    if (pathcomps)
        wordlistDestroy(&pathcomps);

    cwd_message.clean();
    xfree(old_filepath);
    title_url.clean();
    base_href.clean();
    xfree(filepath);
    xfree(dirpath);
}

/**
 * Parse a possible login username:password pair.
 * Produces filled member variables user, password, password_url if anything found.
 *
 * \param login    a decoded Basic authentication credential token or URI user-info token
 * \param escaped  whether to URL-decode the token after extracting user and password
 */
void
Ftp::Gateway::loginParser(const SBuf &login, bool escaped)
{
    debugs(9, 4, "login=" << login << ", escaped=" << escaped);
    debugs(9, 9, "IN : login=" << login << ", escaped=" << escaped << ", user=" << user << ", password=" << password);

    if (login.isEmpty())
        return;

    const SBuf::size_type colonPos = login.find(':');

    /* If there was a username part with at least one character use it.
     * Ignore 0-length username portion, retain what we have already.
     */
    if (colonPos == SBuf::npos || colonPos > 0) {
        const SBuf userName = login.substr(0, colonPos);
        SBuf::size_type upto = userName.copy(user, sizeof(user)-1);
        user[upto]='\0';
        debugs(9, 9, "found user=" << userName << ' ' <<
               (upto != userName.length() ? ", truncated-to=" : ", length=") << upto <<
               ", escaped=" << escaped);
        if (escaped)
            rfc1738_unescape(user);
        debugs(9, 9, "found user=" << user << " (" << strlen(user) << ") unescaped.");
    }

    /* If there was a password part.
     * For 0-length password clobber what we have already, this means explicitly none
     */
    if (colonPos != SBuf::npos) {
        const SBuf pass = login.substr(colonPos+1, SBuf::npos);
        SBuf::size_type upto = pass.copy(password, sizeof(password)-1);
        password[upto]='\0';
        debugs(9, 9, "found password=" << pass << " " <<
               (upto != pass.length() ? ", truncated-to=" : ", length=") << upto <<
               ", escaped=" << escaped);
        if (escaped) {
            rfc1738_unescape(password);
            password_url = 1;
        }
        debugs(9, 9, "found password=" << password << " (" << strlen(password) << ") unescaped.");
    }

    debugs(9, 9, "OUT: login=" << login << ", escaped=" << escaped << ", user=" << user << ", password=" << password);
}

void
Ftp::Gateway::listenForDataChannel(const Comm::ConnectionPointer &conn)
{
    if (!Comm::IsConnOpen(ctrl.conn)) {
        debugs(9, 5, "The control connection to the remote end is closed");
        return;
    }

    assert(!Comm::IsConnOpen(data.conn));

    typedef CommCbMemFunT<Gateway, CommAcceptCbParams> AcceptDialer;
    typedef AsyncCallT<AcceptDialer> AcceptCall;
    RefCount<AcceptCall> call = static_cast<AcceptCall*>(JobCallback(11, 5, AcceptDialer, this, Ftp::Gateway::ftpAcceptDataConnection));
    Subscription::Pointer sub = new CallSubscription<AcceptCall>(call);
    const char *note = entry->url();

    /* open the conn if its not already open */
    if (!Comm::IsConnOpen(conn)) {
        conn->fd = comm_open_listener(SOCK_STREAM, IPPROTO_TCP, conn->local, conn->flags, note);
        if (!Comm::IsConnOpen(conn)) {
            debugs(5, DBG_CRITICAL, HERE << "comm_open_listener failed:" << conn->local << " error: " << errno);
            return;
        }
        debugs(9, 3, HERE << "Unconnected data socket created on " << conn);
    }

    conn->tos = ctrl.conn->tos;
    conn->nfmark = ctrl.conn->nfmark;

    assert(Comm::IsConnOpen(conn));
    AsyncJob::Start(new Comm::TcpAcceptor(conn, note, sub));

    // Ensure we have a copy of the FD opened for listening and a close handler on it.
    data.opened(conn, dataCloser());
    switchTimeoutToDataChannel();
}

void
Ftp::Gateway::timeout(const CommTimeoutCbParams &io)
{
    if (SENT_PASV == state) {
        /* stupid ftp.netscape.com, of FTP server behind stupid firewall rules */
        flags.pasv_supported = false;
        debugs(9, DBG_IMPORTANT, "FTP Gateway timeout in SENT_PASV state");

        // cancel the data connection setup.
        if (data.opener != NULL) {
            data.opener->cancel("timeout");
            data.opener = NULL;
        }
        data.close();
    }

    Ftp::Client::timeout(io);
}

static const char *Month[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static int
is_month(const char *buf)
{
    int i;

    for (i = 0; i < 12; ++i)
        if (!strcasecmp(buf, Month[i]))
            return 1;

    return 0;
}

static void
ftpListPartsFree(ftpListParts ** parts)
{
    safe_free((*parts)->date);
    safe_free((*parts)->name);
    safe_free((*parts)->showname);
    safe_free((*parts)->link);
    safe_free(*parts);
}

#define MAX_TOKENS 64

static ftpListParts *
ftpListParseParts(const char *buf, struct Ftp::GatewayFlags flags)
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

        if (regexec(&scan_ftp_time, year, 0, NULL, 0) != 0) /* Yr | hh:mm */
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
                /* Handle the following four formats:
                 * "MMM DD  YYYY Name"
                 * "MMM DD  YYYYName"
                 * "MMM DD YYYY  Name"
                 * "MMM DD YYYY Name"
                 * Assuming a single space between date and filename
                 * suggested by:  Nathan.Bailey@cc.monash.edu.au and
                 * Mike Battersby <mike@starbug.bofh.asn.au> */
                copyFrom += strlen(tbuf);
                if (strchr(w_space, *copyFrom))
                    ++copyFrom;
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
                    break;  /* not a valid integer */

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
        ftpListPartsFree(&p);   /* cleanup */

    return p;
}

MemBuf *
Ftp::Gateway::htmlifyListEntry(const char *line)
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
        html->appendf("<tr><td colspan=\"5\">%s</td></tr>\n", line);
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
        html->appendf("<tr class=\"entry\"><td colspan=\"5\">%s</td></tr>\n", line);

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
        strcat(href, "/");  /* margin is allocated above */
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
    html->appendf("<tr class=\"entry\">"
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
Ftp::Gateway::parseListing()
{
    char *buf = data.readBuf->content();
    char *sbuf;         /* NULL-terminated copy of termedBuf */
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
            delete t;
        }
    }

    debugs(9, 7, HERE << "Done.");
    data.readBuf->consume(usable);
    memFree(line, MEM_4K_BUF);
    xfree(sbuf);
}

void
Ftp::Gateway::processReplyBody()
{
    debugs(9, 3, status());

    if (request->method == Http::METHOD_HEAD && (flags.isdir || theSize != -1)) {
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
        abortAll("entry aborted after calling appendSuccessHeader()");
        return;
    }

#if USE_ADAPTATION

    if (adaptationAccessCheckPending) {
        debugs(9, 3, "returning from Ftp::Gateway::processReplyBody due to adaptationAccessCheckPending");
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
 \retval 1  if we have everything needed to complete this request.
 \retval 0  if something is missing.
 */
int
Ftp::Gateway::checkAuth(const HttpHeader * req_hdr)
{
    /* default username */
    xstrncpy(user, "anonymous", MAX_URL);

#if HAVE_AUTH_MODULE_BASIC
    /* Check HTTP Authorization: headers (better than defaults, but less than URL) */
    const SBuf auth(req_hdr->getAuth(Http::HdrType::AUTHORIZATION, "Basic"));
    if (!auth.isEmpty()) {
        flags.authenticated = 1;
        loginParser(auth, false);
    }
    /* we fail with authorization-required error later IFF the FTP server requests it */
#endif

    /* Test URL login syntax. Overrides any headers received. */
    loginParser(request->url.userInfo(), true);

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

    return 0;           /* different username */
}

void
Ftp::Gateway::checkUrlpath()
{
    static SBuf str_type_eq("type=");
    auto t = request->url.path().rfind(';');

    if (t != SBuf::npos) {
        auto filenameEnd = t-1;
        if (request->url.path().substr(++t).cmp(str_type_eq, str_type_eq.length()) == 0) {
            t += str_type_eq.length();
            typecode = (char)xtoupper(request->url.path()[t]);
            request->url.path(request->url.path().substr(0,filenameEnd));
        }
    }

    int l = request->url.path().length();
    /* check for null path */

    if (!l) {
        flags.isdir = 1;
        flags.root_dir = 1;
        flags.need_base_href = 1;   /* Work around broken browsers */
    } else if (!request->url.path().cmp("/%2f/")) {
        /* UNIX root directory */
        flags.isdir = 1;
        flags.root_dir = 1;
    } else if ((l >= 1) && (request->url.path()[l-1] == '/')) {
        /* Directory URL, ending in / */
        flags.isdir = 1;

        if (l == 1)
            flags.root_dir = 1;
    } else {
        flags.dir_slash = 1;
    }
}

void
Ftp::Gateway::buildTitleUrl()
{
    title_url = "ftp://";

    if (strcmp(user, "anonymous")) {
        title_url.append(user);
        title_url.append("@");
    }

    SBuf authority = request->url.authority(request->url.getScheme() != AnyP::PROTO_FTP);

    title_url.append(authority.rawContent(), authority.length());
    title_url.append(request->url.path().rawContent(), request->url.path().length());

    base_href = "ftp://";

    if (strcmp(user, "anonymous") != 0) {
        base_href.append(rfc1738_escape_part(user));

        if (password_url) {
            base_href.append(":");
            base_href.append(rfc1738_escape_part(password));
        }

        base_href.append("@");
    }

    base_href.append(authority.rawContent(), authority.length());
    base_href.append(request->url.path().rawContent(), request->url.path().length());
    base_href.append("/");
}

void
Ftp::Gateway::start()
{
    if (!checkAuth(&request->header)) {
        /* create appropriate reply */
        SBuf realm(ftpRealm()); // local copy so SBuf will not disappear too early
        HttpReply *reply = ftpAuthRequired(request, realm);
        entry->replaceHttpReply(reply);
        serverComplete();
        return;
    }

    checkUrlpath();
    buildTitleUrl();
    debugs(9, 5, "FD " << (ctrl.conn ? ctrl.conn->fd : -1) << " : host=" << request->url.host() <<
           ", path=" << request->url.path() << ", user=" << user << ", passwd=" << password);
    state = BEGIN;
    Ftp::Client::start();
}

/* ====================================================================== */

void
Ftp::Gateway::handleControlReply()
{
    Ftp::Client::handleControlReply();
    if (ctrl.message == NULL)
        return; // didn't get complete reply yet

    /* Copy the message except for the last line to cwd_message to be
     * printed in error messages.
     */
    for (wordlist *w = ctrl.message; w && w->next; w = w->next) {
        cwd_message.append('\n');
        cwd_message.append(w->key);
    }

    FTP_SM_FUNCS[state] (this);
}

/* ====================================================================== */

static void
ftpReadWelcome(Ftp::Gateway * ftpState)
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
Ftp::Gateway::loginFailed()
{
    ErrorState *err = NULL;

    if ((state == SENT_USER || state == SENT_PASS) && ctrl.replycode >= 400) {
        if (ctrl.replycode == 421 || ctrl.replycode == 426) {
            // 421/426 - Service Overload - retry permitted.
            err = new ErrorState(ERR_FTP_UNAVAILABLE, Http::scServiceUnavailable, fwd->request);
        } else if (ctrl.replycode >= 430 && ctrl.replycode <= 439) {
            // 43x - Invalid or Credential Error - retry challenge required.
            err = new ErrorState(ERR_FTP_FORBIDDEN, Http::scUnauthorized, fwd->request);
        } else if (ctrl.replycode >= 530 && ctrl.replycode <= 539) {
            // 53x - Credentials Missing - retry challenge required
            if (password_url) // but they were in the URI! major fail.
                err = new ErrorState(ERR_FTP_FORBIDDEN, Http::scForbidden, fwd->request);
            else
                err = new ErrorState(ERR_FTP_FORBIDDEN, Http::scUnauthorized, fwd->request);
        }
    }

    if (!err) {
        ftpFail(this);
        return;
    }

    failed(ERR_NONE, ctrl.replycode, err);
    // any other problems are general falures.

    HttpReply *newrep = err->BuildHttpReply();
    delete err;

#if HAVE_AUTH_MODULE_BASIC
    /* add Authenticate header */
    // XXX: performance regression. c_str() may reallocate
    SBuf realm(ftpRealm()); // local copy so SBuf will not disappear too early
    newrep->header.putAuth("Basic", realm.c_str());
#endif

    // add it to the store entry for response....
    entry->replaceHttpReply(newrep);
    serverComplete();
}

SBuf
Ftp::Gateway::ftpRealm()
{
    SBuf realm;

    /* This request is not fully authenticated */
    realm.appendf("FTP %s ", user);
    if (!request)
        realm.append("unknown", 7);
    else {
        realm.append(request->url.host());
        if (request->url.port() != 21)
            realm.appendf(" port %d", request->url.port());
    }
    return realm;
}

static void
ftpSendUser(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendUser"))
        return;

    if (ftpState->proxy_host != NULL)
        snprintf(cbuf, CTRL_BUFLEN, "USER %s@%s\r\n", ftpState->user, ftpState->request->url.host());
    else
        snprintf(cbuf, CTRL_BUFLEN, "USER %s\r\n", ftpState->user);

    ftpState->writeCommand(cbuf);

    ftpState->state = Ftp::Client::SENT_USER;
}

static void
ftpReadUser(Ftp::Gateway * ftpState)
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

static void
ftpSendPass(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendPass"))
        return;

    snprintf(cbuf, CTRL_BUFLEN, "PASS %s\r\n", ftpState->password);
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_PASS;
}

static void
ftpReadPass(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE << "code=" << code);

    if (code == 230) {
        ftpSendType(ftpState);
    } else {
        ftpState->loginFailed();
    }
}

static void
ftpSendType(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendType"))
        return;

    /*
     * Ref section 3.2.2 of RFC 1738
     */
    char mode = ftpState->typecode;

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
            auto t = ftpState->request->url.path().rfind('/');
            // XXX: performance regression, c_str() may reallocate
            SBuf filename = ftpState->request->url.path().substr(t != SBuf::npos ? t + 1 : 0);
            mode = mimeGetTransferMode(filename.c_str());
        }

        break;
    }

    if (mode == 'I')
        ftpState->flags.binary = 1;
    else
        ftpState->flags.binary = 0;

    snprintf(cbuf, CTRL_BUFLEN, "TYPE %c\r\n", mode);

    ftpState->writeCommand(cbuf);

    ftpState->state = Ftp::Client::SENT_TYPE;
}

static void
ftpReadType(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    char *path;
    char *d, *p;
    debugs(9, 3, HERE << "code=" << code);

    if (code == 200) {
        p = path = SBufToCstring(ftpState->request->url.path());

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

static void
ftpTraverseDirectory(Ftp::Gateway * ftpState)
{
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
    ftpState->filepath = wordlistChopHead(& ftpState->pathcomps);

    /* Check if we are to CWD or RETR */
    if (ftpState->pathcomps != NULL || ftpState->flags.isdir) {
        ftpSendCwd(ftpState);
    } else {
        debugs(9, 3, HERE << "final component is probably a file");
        ftpGetFile(ftpState);
        return;
    }
}

static void
ftpSendCwd(Ftp::Gateway * ftpState)
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

    ftpState->state = Ftp::Client::SENT_CWD;
}

static void
ftpReadCwd(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code >= 200 && code < 300) {
        /* CWD OK */
        ftpState->unhack();

        /* Reset cwd_message to only include the last message */
        ftpState->cwd_message.reset("");
        for (wordlist *w = ftpState->ctrl.message; w; w = w->next) {
            ftpState->cwd_message.append('\n');
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

static void
ftpSendMkdir(Ftp::Gateway * ftpState)
{
    char *path = NULL;

    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendMkdir"))
        return;

    path = ftpState->filepath;
    debugs(9, 3, HERE << "with path=" << path);
    snprintf(cbuf, CTRL_BUFLEN, "MKD %s\r\n", path);
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_MKDIR;
}

static void
ftpReadMkdir(Ftp::Gateway * ftpState)
{
    char *path = ftpState->filepath;
    int code = ftpState->ctrl.replycode;

    debugs(9, 3, HERE << "path " << path << ", code " << code);

    if (code == 257) {      /* success */
        ftpSendCwd(ftpState);
    } else if (code == 550) {   /* dir exists */

        if (ftpState->flags.put_mkdir) {
            ftpState->flags.put_mkdir = 1;
            ftpSendCwd(ftpState);
        } else
            ftpSendReply(ftpState);
    } else
        ftpSendReply(ftpState);
}

static void
ftpGetFile(Ftp::Gateway * ftpState)
{
    assert(*ftpState->filepath != '\0');
    ftpState->flags.isdir = 0;
    ftpSendMdtm(ftpState);
}

static void
ftpListDir(Ftp::Gateway * ftpState)
{
    if (ftpState->flags.dir_slash) {
        debugs(9, 3, HERE << "Directory path did not end in /");
        ftpState->title_url.append("/");
        ftpState->flags.isdir = 1;
    }

    ftpSendPassive(ftpState);
}

static void
ftpSendMdtm(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendMdtm"))
        return;

    assert(*ftpState->filepath != '\0');
    snprintf(cbuf, CTRL_BUFLEN, "MDTM %s\r\n", ftpState->filepath);
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_MDTM;
}

static void
ftpReadMdtm(Ftp::Gateway * ftpState)
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

static void
ftpSendSize(Ftp::Gateway * ftpState)
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
        ftpState->state = Ftp::Client::SENT_SIZE;
    } else
        /* Skip to next state no non-binary transfers */
        ftpSendPassive(ftpState);
}

static void
ftpReadSize(Ftp::Gateway * ftpState)
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

static void
ftpReadEPSV(Ftp::Gateway* ftpState)
{
    Ip::Address srvAddr; // unused
    if (ftpState->handleEpsvReply(srvAddr)) {
        if (ftpState->ctrl.message == NULL)
            return; // didn't get complete reply yet

        ftpState->connectDataChannel();
    }
}

/** Send Passive connection request.
 * Default method is to use modern EPSV request.
 * The failover mechanism should check for previous state and re-call with alternates on failure.
 */
static void
ftpSendPassive(Ftp::Gateway * ftpState)
{
    /** Checks the server control channel is still available before running. */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendPassive"))
        return;

    debugs(9, 3, HERE);

    /** \par
      * Checks for 'HEAD' method request and passes off for special handling by Ftp::Gateway::processHeadResponse(). */
    if (ftpState->request->method == Http::METHOD_HEAD && (ftpState->flags.isdir || ftpState->theSize != -1)) {
        ftpState->processHeadResponse(); // may call serverComplete
        return;
    }

    if (ftpState->sendPassive()) {
        // SENT_EPSV_ALL blocks other non-EPSV connections being attempted
        if (ftpState->state == Ftp::Client::SENT_EPSV_ALL)
            ftpState->flags.epsv_all_sent = true;
    }
}

void
Ftp::Gateway::processHeadResponse()
{
    debugs(9, 5, HERE << "handling HEAD response");
    ftpSendQuit(this);
    appendSuccessHeader();

    /*
     * On rare occasions I'm seeing the entry get aborted after
     * readControlReply() and before here, probably when
     * trying to write to the client.
     */
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortAll("entry aborted while processing HEAD");
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

static void
ftpReadPasv(Ftp::Gateway * ftpState)
{
    Ip::Address srvAddr; // unused
    if (ftpState->handlePasvReply(srvAddr))
        ftpState->connectDataChannel();
    else {
        ftpFail(ftpState);
        // Currently disabled, does not work correctly:
        // ftpSendEPRT(ftpState);
        return;
    }
}

void
Ftp::Gateway::dataChannelConnected(const CommConnectCbParams &io)
{
    debugs(9, 3, HERE);
    data.opener = NULL;

    if (io.flag != Comm::OK) {
        debugs(9, 2, HERE << "Failed to connect. Retrying via another method.");

        // ABORT on timeouts. server may be waiting on a broken TCP link.
        if (io.xerrno == Comm::TIMEOUT)
            writeCommand("ABOR\r\n");

        // try another connection attempt with some other method
        ftpSendPassive(this);
        return;
    }

    data.opened(io.conn, dataCloser());
    ftpRestOrList(this);
}

static void
ftpOpenListenSocket(Ftp::Gateway * ftpState, int fallback)
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

    if (!Comm::IsConnOpen(ftpState->ctrl.conn)) {
        debugs(9, 5, "The control connection to the remote end is closed");
        return;
    }

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
        errno = 0;
        if (setsockopt(ftpState->ctrl.conn->fd, SOL_SOCKET, SO_REUSEADDR,
                       (char *) &on, sizeof(on)) == -1) {
            int xerrno = errno;
            // SO_REUSEADDR is only an optimization, no need to be verbose about error
            debugs(9, 4, "setsockopt failed: " << xstrerr(xerrno));
        }
        ftpState->ctrl.conn->flags |= COMM_REUSEADDR;
        temp->flags |= COMM_REUSEADDR;
    } else {
        /* if not running in fallback mode a new port needs to be retrieved */
        temp->local.port(0);
    }

    ftpState->listenForDataChannel(temp);
}

static void
ftpSendPORT(Ftp::Gateway * ftpState)
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
        if ( ftpState->data.listenConn != NULL && !ftpState->data.listenConn->local.isIPv4() ) {
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
    ftpState->data.listenConn->local.getAddrInfo(AI, AF_INET);
    unsigned char *addrptr = (unsigned char *) &((struct sockaddr_in*)AI->ai_addr)->sin_addr;
    unsigned char *portptr = (unsigned char *) &((struct sockaddr_in*)AI->ai_addr)->sin_port;
    snprintf(cbuf, CTRL_BUFLEN, "PORT %d,%d,%d,%d,%d,%d\r\n",
             addrptr[0], addrptr[1], addrptr[2], addrptr[3],
             portptr[0], portptr[1]);
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_PORT;

    Ip::Address::FreeAddr(AI);
}

static void
ftpReadPORT(Ftp::Gateway * ftpState)
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

#if 0
static void
ftpSendEPRT(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendEPRT"))
        return;

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
             ( ftpState->data.listenConn->local.isIPv6() ? 2 : 1 ),
             ftpState->data.listenConn->local.toStr(buf,MAX_IPSTRLEN),
             ftpState->data.listenConn->local.port() );

    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_EPRT;
}
#endif

static void
ftpReadEPRT(Ftp::Gateway * ftpState)
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

/** "read" handler to accept FTP data connections.
 *
 \param io    comm accept(2) callback parameters
 */
void
Ftp::Gateway::ftpAcceptDataConnection(const CommAcceptCbParams &io)
{
    debugs(9, 3, HERE);

    if (!Comm::IsConnOpen(ctrl.conn)) { /*Close handlers will cleanup*/
        debugs(9, 5, "The control connection to the remote end is closed");
        return;
    }

    if (io.flag != Comm::OK) {
        data.listenConn->close();
        data.listenConn = NULL;
        debugs(9, DBG_IMPORTANT, "FTP AcceptDataConnection: " << io.conn << ": " << xstrerr(io.xerrno));
        /** \todo Need to send error message on control channel*/
        ftpFail(this);
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortAll("entry aborted when accepting data conn");
        data.listenConn->close();
        data.listenConn = NULL;
        io.conn->close();
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

    /** On Comm::OK start using the accepted data socket and discard the temporary listen socket. */
    data.close();
    data.opened(io.conn, dataCloser());
    data.addr(io.conn->remote);

    debugs(9, 3, HERE << "Connected data socket on " <<
           io.conn << ". FD table says: " <<
           "ctrl-peer= " << fd_table[ctrl.conn->fd].ipaddr << ", " <<
           "data-peer= " << fd_table[data.conn->fd].ipaddr);

    assert(haveControlChannel("ftpAcceptDataConnection"));
    assert(ctrl.message == NULL);

    // Ctrl channel operations will determine what happens to this data connection
}

static void
ftpRestOrList(Ftp::Gateway * ftpState)
{
    debugs(9, 3, HERE);

    if (ftpState->typecode == 'D') {
        ftpState->flags.isdir = 1;

        if (ftpState->flags.put) {
            ftpSendMkdir(ftpState); /* PUT name;type=d */
        } else {
            ftpSendNlst(ftpState);  /* GET name;type=d  sec 3.2.2 of RFC 1738 */
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

static void
ftpSendStor(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendStor"))
        return;

    debugs(9, 3, HERE);

    if (ftpState->filepath != NULL) {
        /* Plain file upload */
        snprintf(cbuf, CTRL_BUFLEN, "STOR %s\r\n", ftpState->filepath);
        ftpState->writeCommand(cbuf);
        ftpState->state = Ftp::Client::SENT_STOR;
    } else if (ftpState->request->header.getInt64(Http::HdrType::CONTENT_LENGTH) > 0) {
        /* File upload without a filename. use STOU to generate one */
        snprintf(cbuf, CTRL_BUFLEN, "STOU\r\n");
        ftpState->writeCommand(cbuf);
        ftpState->state = Ftp::Client::SENT_STOR;
    } else {
        /* No file to transfer. Only create directories if needed */
        ftpSendReply(ftpState);
    }
}

/// \deprecated use ftpState->readStor() instead.
static void
ftpReadStor(Ftp::Gateway * ftpState)
{
    ftpState->readStor();
}

void Ftp::Gateway::readStor()
{
    int code = ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && Comm::IsConnOpen(data.conn))) {
        if (!originalRequest()->body_pipe) {
            debugs(9, 3, "zero-size STOR?");
            state = WRITING_DATA; // make ftpWriteTransferDone() responsible
            dataComplete(); // XXX: keep in sync with doneSendingRequestBody()
            return;
        }

        if (!startRequestBodyFlow()) { // register to receive body data
            ftpFail(this);
            return;
        }

        /* When client status is 125, or 150 and the data connection is open, Begin data transfer. */
        debugs(9, 3, HERE << "starting data transfer");
        switchTimeoutToDataChannel();
        sendMoreRequestBody();
        fwd->dontRetry(true); // do not permit re-trying if the body was sent.
        state = WRITING_DATA;
        debugs(9, 3, HERE << "writing data channel");
    } else if (code == 150) {
        /* When client code is 150 with no data channel, Accept data channel. */
        debugs(9, 3, "ftpReadStor: accepting data channel");
        listenForDataChannel(data.conn);
    } else {
        debugs(9, DBG_IMPORTANT, HERE << "Unexpected reply code "<< std::setfill('0') << std::setw(3) << code);
        ftpFail(this);
    }
}

static void
ftpSendRest(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendRest"))
        return;

    debugs(9, 3, HERE);

    snprintf(cbuf, CTRL_BUFLEN, "REST %" PRId64 "\r\n", ftpState->restart_offset);
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_REST;
}

int
Ftp::Gateway::restartable()
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

static void
ftpReadRest(Ftp::Gateway * ftpState)
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

static void
ftpSendList(Ftp::Gateway * ftpState)
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
    ftpState->state = Ftp::Client::SENT_LIST;
}

static void
ftpSendNlst(Ftp::Gateway * ftpState)
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
    ftpState->state = Ftp::Client::SENT_NLST;
}

static void
ftpReadList(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && Comm::IsConnOpen(ftpState->data.conn))) {
        /* Begin data transfer */
        debugs(9, 3, HERE << "begin data transfer from " << ftpState->data.conn->remote << " (" << ftpState->data.conn->local << ")");
        ftpState->switchTimeoutToDataChannel();
        ftpState->maybeReadVirginBody();
        ftpState->state = Ftp::Client::READING_DATA;
        return;
    } else if (code == 150) {
        /* Accept data channel */
        debugs(9, 3, HERE << "accept data channel from " << ftpState->data.conn->remote << " (" << ftpState->data.conn->local << ")");
        ftpState->listenForDataChannel(ftpState->data.conn);
        return;
    } else if (!ftpState->flags.tried_nlst && code > 300) {
        ftpSendNlst(ftpState);
    } else {
        ftpFail(ftpState);
        return;
    }
}

static void
ftpSendRetr(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendRetr"))
        return;

    debugs(9, 3, HERE);

    assert(ftpState->filepath != NULL);
    snprintf(cbuf, CTRL_BUFLEN, "RETR %s\r\n", ftpState->filepath);
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_RETR;
}

static void
ftpReadRetr(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (code == 125 || (code == 150 && Comm::IsConnOpen(ftpState->data.conn))) {
        /* Begin data transfer */
        debugs(9, 3, HERE << "begin data transfer from " << ftpState->data.conn->remote << " (" << ftpState->data.conn->local << ")");
        ftpState->switchTimeoutToDataChannel();
        ftpState->maybeReadVirginBody();
        ftpState->state = Ftp::Client::READING_DATA;
    } else if (code == 150) {
        /* Accept data channel */
        ftpState->listenForDataChannel(ftpState->data.conn);
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
Ftp::Gateway::completedListing()
{
    assert(entry);
    entry->lock("Ftp::Gateway");
    ErrorState ferr(ERR_DIR_LISTING, Http::scOkay, request);
    ferr.ftp.listing = &listing;
    ferr.ftp.cwd_msg = xstrdup(cwd_message.size()? cwd_message.termedBuf() : "");
    ferr.ftp.server_msg = ctrl.message;
    ctrl.message = NULL;
    entry->replaceHttpReply( ferr.BuildHttpReply() );
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->flush();
    entry->unlock("Ftp::Gateway");
}

static void
ftpReadTransferDone(Ftp::Gateway * ftpState)
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
    } else {            /* != 226 */
        debugs(9, DBG_IMPORTANT, HERE << "Got code " << code << " after reading data");
        ftpState->failed(ERR_FTP_FAILURE, 0);
        /* failed closes ctrl.conn and frees ftpState */
        return;
    }
}

// premature end of the request body
void
Ftp::Gateway::handleRequestBodyProducerAborted()
{
    Client::handleRequestBodyProducerAborted();
    debugs(9, 3, HERE << "ftpState=" << this);
    failed(ERR_READ_ERROR, 0);
}

static void
ftpWriteTransferDone(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debugs(9, 3, HERE);

    if (!(code == 226 || code == 250)) {
        debugs(9, DBG_IMPORTANT, HERE << "Got code " << code << " after sending data");
        ftpState->failed(ERR_FTP_PUT_ERROR, 0);
        return;
    }

    ftpState->entry->timestampsSet();   /* XXX Is this needed? */
    ftpSendReply(ftpState);
}

static void
ftpSendQuit(Ftp::Gateway * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendQuit"))
        return;

    snprintf(cbuf, CTRL_BUFLEN, "QUIT\r\n");
    ftpState->writeCommand(cbuf);
    ftpState->state = Ftp::Client::SENT_QUIT;
}

/** Completes a client FTP operation with success or other page
 *  generated and stored in the entry field by the code issuing QUIT.
 */
static void
ftpReadQuit(Ftp::Gateway * ftpState)
{
    ftpState->serverComplete();
}

static void
ftpTrySlashHack(Ftp::Gateway * ftpState)
{
    char *path;
    ftpState->flags.try_slash_hack = 1;
    /* Free old paths */

    debugs(9, 3, HERE);

    if (ftpState->pathcomps)
        wordlistDestroy(&ftpState->pathcomps);

    safe_free(ftpState->filepath);

    /* Build the new path (urlpath begins with /) */
    path = SBufToCstring(ftpState->request->url.path());

    rfc1738_unescape(path);

    ftpState->filepath = path;

    /* And off we go */
    ftpGetFile(ftpState);
}

/**
 * Forget hack status. Next error is shown to the user
 */
void
Ftp::Gateway::unhack()
{
    debugs(9, 3, HERE);

    if (old_request != NULL) {
        safe_free(old_request);
        safe_free(old_reply);
    }
}

void
Ftp::Gateway::hackShortcut(FTPSM * nextState)
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

static void
ftpFail(Ftp::Gateway *ftpState)
{
    const bool slashHack = ftpState->request->url.path().caseCmp("/%2f", 4)==0;
    int code = ftpState->ctrl.replycode;
    err_type error_code = ERR_NONE;

    debugs(9, 6, "state " << ftpState->state <<
           " reply code " << code << "flags(" <<
           (ftpState->flags.isdir?"IS_DIR,":"") <<
           (ftpState->flags.try_slash_hack?"TRY_SLASH_HACK":"") << "), " <<
           "mdtm=" << ftpState->mdtm << ", size=" << ftpState->theSize <<
           "slashhack=" << (slashHack? "T":"F"));

    /* Try the / hack to support "Netscape" FTP URL's for retreiving files */
    if (!ftpState->flags.isdir &&   /* Not a directory */
            !ftpState->flags.try_slash_hack && !slashHack && /* Not doing slash hack */
            ftpState->mdtm <= 0 && ftpState->theSize < 0) { /* Not known as a file */

        switch (ftpState->state) {

        case Ftp::Client::SENT_CWD:

        case Ftp::Client::SENT_RETR:
            /* Try the / hack */
            ftpState->hackShortcut(ftpTrySlashHack);
            return;

        default:
            break;
        }
    }

    Http::StatusCode sc = ftpState->failedHttpStatus(error_code);
    ErrorState *ftperr = new ErrorState(error_code, sc, ftpState->fwd->request);
    ftpState->failed(error_code, code, ftperr);
    ftperr->detailError(code);
    HttpReply *newrep = ftperr->BuildHttpReply();
    delete ftperr;

    ftpState->entry->replaceHttpReply(newrep);
    ftpSendQuit(ftpState);
}

Http::StatusCode
Ftp::Gateway::failedHttpStatus(err_type &error)
{
    if (error == ERR_NONE) {
        switch (state) {

        case SENT_USER:

        case SENT_PASS:

            if (ctrl.replycode > 500) {
                error = ERR_FTP_FORBIDDEN;
                return password_url ? Http::scForbidden : Http::scUnauthorized;
            } else if (ctrl.replycode == 421) {
                error = ERR_FTP_UNAVAILABLE;
                return Http::scServiceUnavailable;
            }
            break;

        case SENT_CWD:

        case SENT_RETR:
            if (ctrl.replycode == 550) {
                error = ERR_FTP_NOT_FOUND;
                return Http::scNotFound;
            }
            break;

        default:
            break;
        }
    }
    return Ftp::Client::failedHttpStatus(error);
}

static void
ftpSendReply(Ftp::Gateway * ftpState)
{
    int code = ftpState->ctrl.replycode;
    Http::StatusCode http_code;
    err_type err_code = ERR_NONE;

    debugs(9, 3, HERE << ftpState->entry->url() << ", code " << code);

    if (cbdataReferenceValid(ftpState))
        debugs(9, 5, HERE << "ftpState (" << ftpState << ") is valid!");

    if (code == 226 || code == 250) {
        err_code = (ftpState->mdtm > 0) ? ERR_FTP_PUT_MODIFIED : ERR_FTP_PUT_CREATED;
        http_code = (ftpState->mdtm > 0) ? Http::scAccepted : Http::scCreated;
    } else if (code == 227) {
        err_code = ERR_FTP_PUT_CREATED;
        http_code = Http::scCreated;
    } else {
        err_code = ERR_FTP_PUT_ERROR;
        http_code = Http::scInternalServerError;
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
Ftp::Gateway::appendSuccessHeader()
{
    debugs(9, 3, HERE);

    if (flags.http_header_sent)
        return;

    HttpReply *reply = new HttpReply;

    flags.http_header_sent = 1;

    assert(entry->isEmpty());

    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);

    entry->buffer();    /* released when done processing current data payload */

    SBuf urlPath = request->url.path();
    auto t = urlPath.rfind('/');
    SBuf filename = urlPath.substr(t != SBuf::npos ? t : 0);

    const char *mime_type = NULL;
    const char *mime_enc = NULL;

    if (flags.isdir) {
        mime_type = "text/html";
    } else {
        switch (typecode) {

        case 'I':
            mime_type = "application/octet-stream";
            // XXX: performance regression, c_str() may reallocate
            mime_enc = mimeGetContentEncoding(filename.c_str());
            break;

        case 'A':
            mime_type = "text/plain";
            break;

        default:
            // XXX: performance regression, c_str() may reallocate
            mime_type = mimeGetContentType(filename.c_str());
            mime_enc = mimeGetContentEncoding(filename.c_str());
            break;
        }
    }

    /* set standard stuff */

    if (0 == getCurrentOffset()) {
        /* Full reply */
        reply->setHeaders(Http::scOkay, "Gatewaying", mime_type, theSize, mdtm, -2);
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
        reply->setHeaders(Http::scOkay, "Gatewaying", mime_type, theSize, mdtm, -2);
    } else {
        /* Partial reply */
        HttpHdrRangeSpec range_spec;
        range_spec.offset = getCurrentOffset();
        range_spec.length = theSize - getCurrentOffset();
        reply->setHeaders(Http::scPartialContent, "Gatewaying", mime_type, theSize - getCurrentOffset(), mdtm, -2);
        httpHeaderAddContRange(&reply->header, range_spec, theSize);
    }

    /* additional info */
    if (mime_enc)
        reply->header.putStr(Http::HdrType::CONTENT_ENCODING, mime_enc);

    reply->sources |= HttpMsg::srcFtp;
    setVirginReply(reply);
    adaptOrFinalizeReply();
}

void
Ftp::Gateway::haveParsedReplyHeaders()
{
    Client::haveParsedReplyHeaders();

    StoreEntry *e = entry;

    e->timestampsSet();

    // makePublic() if allowed/possible or release() otherwise
    if (flags.authenticated || // authenticated requests can't be cached
            getCurrentOffset() ||
            !e->makePublic()) {
        e->release();
    }
}

HttpReply *
Ftp::Gateway::ftpAuthRequired(HttpRequest * request, SBuf &realm)
{
    ErrorState err(ERR_CACHE_ACCESS_DENIED, Http::scUnauthorized, request);
    HttpReply *newrep = err.BuildHttpReply();
#if HAVE_AUTH_MODULE_BASIC
    /* add Authenticate header */
    // XXX: performance regression. c_str() may reallocate
    newrep->header.putAuth("Basic", realm.c_str());
#endif
    return newrep;
}

const SBuf &
Ftp::UrlWith2f(HttpRequest * request)
{
    SBuf newbuf("%2f");

    if (request->url.getScheme() != AnyP::PROTO_FTP) {
        static const SBuf nil;
        return nil;
    }

    if (request->url.path()[0] == '/') {
        newbuf.append(request->url.path());
        request->url.path(newbuf);
    } else if (!request->url.path().startsWith(newbuf)) {
        newbuf.append(request->url.path().substr(1));
        request->url.path(newbuf);
    }

    return request->effectiveRequestUri();
}

void
Ftp::Gateway::printfReplyBody(const char *fmt, ...)
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
Ftp::Gateway::writeReplyBody(const char *dataToWrite, size_t dataLength)
{
    debugs(9, 5, HERE << "writing " << dataLength << " bytes to the reply");
    addVirginReplyBody(dataToWrite, dataLength);
}

/**
 * A hack to ensure we do not double-complete on the forward entry.
 *
 \todo Ftp::Gateway logic should probably be rewritten to avoid
 *  double-completion or FwdState should be rewritten to allow it.
 */
void
Ftp::Gateway::completeForwarding()
{
    if (fwd == NULL || flags.completed_forwarding) {
        debugs(9, 3, "avoid double-complete on FD " <<
               (ctrl.conn ? ctrl.conn->fd : -1) << ", Data FD " << data.conn->fd <<
               ", this " << this << ", fwd " << fwd);
        return;
    }

    flags.completed_forwarding = true;
    Client::completeForwarding();
}

/**
 * Have we lost the FTP server control channel?
 *
 \retval true   The server control channel is available.
 \retval false  The server control channel is not available.
 */
bool
Ftp::Gateway::haveControlChannel(const char *caller_name) const
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

bool
Ftp::Gateway::mayReadVirginReplyBody() const
{
    // TODO: Can we do what Ftp::Relay::mayReadVirginReplyBody() does instead?
    return !doneWithServer();
}

AsyncJob::Pointer
Ftp::StartGateway(FwdState *const fwdState)
{
    return AsyncJob::Start(new Ftp::Gateway(fwdState));
}

