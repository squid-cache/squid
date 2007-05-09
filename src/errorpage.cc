
/*
 * $Id: errorpage.cc,v 1.225 2007/05/09 09:07:39 wessels Exp $
 *
 * DEBUG: section 4     Error Generation
 * AUTHOR: Duane Wessels
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

/*
 * Abstract:  These routines are used to generate error messages to be
 *              sent to clients.  The error type is used to select between
 *              the various message formats. (formats are stored in the
 *              Config.errorDirectory)
 */

#include "errorpage.h"
#include "AuthUserRequest.h"
#include "SquidTime.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "fde.h"
#include "MemBuf.h"
#include "URLScheme.h"
#include "wordlist.h"

CBDATA_CLASS_INIT(ErrorState);

/* local types */

typedef struct
{
    int id;
    char *page_name;
}

ErrorDynamicPageInfo;

/* local constant and vars */

/*
 * note: hard coded error messages are not appended with %S automagically
 * to give you more control on the format
 */

static const struct
{
    int type;			/* and page_id */
    const char *text;
}

error_hard_text[] = {

                        {
                            ERR_SQUID_SIGNATURE,
                            "\n<BR clear=\"all\">\n"
                            "<HR noshade size=\"1px\">\n"
                            "<ADDRESS>\n"
                            "Generated %T by %h (%s)\n"
                            "</ADDRESS>\n"
                            "</BODY></HTML>\n"
                        },
                        {
                            TCP_RESET,
                            "reset"
                        }
                    };

static Vector<ErrorDynamicPageInfo *> ErrorDynamicPages;

/* local prototypes */

static const int error_hard_text_count = sizeof(error_hard_text) / sizeof(*error_hard_text);
static char **error_text = NULL;
static int error_page_count = 0;

static char *errorTryLoadText(const char *page_name, const char *dir);
static char *errorLoadText(const char *page_name);
static const char *errorFindHardText(err_type type);
static ErrorDynamicPageInfo *errorDynamicPageInfoCreate(int id, const char *page_name);
static void errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info);
static MemBuf *errorBuildContent(ErrorState * err);
static int errorDump(ErrorState * err, MemBuf * mb);
static const char *errorConvert(char token, ErrorState * err);
static IOCB errorSendComplete;


err_type &operator++ (err_type &anErr)
{
    int tmp = (int)anErr;
    anErr = (err_type)(++tmp);
    return anErr;
}

int operator - (err_type const &anErr, err_type const &anErr2)
{
    return (int)anErr - (int)anErr2;
}

/*
 * Function:  errorInitialize
 *
 * Abstract:  This function finds the error messages formats, and stores
 *            them in error_text[];
 *
 * Global effects:
 *            error_text[] - is modified
 */
void
errorInitialize(void)
{
    err_type i;
    const char *text;
    error_page_count = ERR_MAX + ErrorDynamicPages.size();
    error_text = static_cast<char **>(xcalloc(error_page_count, sizeof(char *)));

    for (i = ERR_NONE, ++i; i < error_page_count; ++i) {
        safe_free(error_text[i]);
        /* hard-coded ? */

        if ((text = errorFindHardText(i)))
            error_text[i] = xstrdup(text);
        else if (i < ERR_MAX) {
            /* precompiled ? */
            error_text[i] = errorLoadText(err_type_str[i]);
        } else {
            /* dynamic */
            ErrorDynamicPageInfo *info = ErrorDynamicPages.items[i - ERR_MAX];
            assert(info && info->id == i && info->page_name);

            if (strchr(info->page_name, ':') == NULL) {
                /* Not on redirected errors... */
                error_text[i] = errorLoadText(info->page_name);
            }
        }
    }
}

void
errorClean(void)
{
    if (error_text) {
        int i;

        for (i = ERR_NONE + 1; i < error_page_count; i++)
            safe_free(error_text[i]);

        safe_free(error_text);
    }

    while (ErrorDynamicPages.size())
        errorDynamicPageInfoDestroy(ErrorDynamicPages.pop_back());

    error_page_count = 0;
}

static const char *
errorFindHardText(err_type type)
{
    int i;

    for (i = 0; i < error_hard_text_count; i++)
        if (error_hard_text[i].type == type)
            return error_hard_text[i].text;

    return NULL;
}


static char *
errorLoadText(const char *page_name)
{
    /* test configured location */
    char *text = errorTryLoadText(page_name, Config.errorDirectory);
    /* test default location if failed */

    if (!text && strcmp(Config.errorDirectory, DEFAULT_SQUID_ERROR_DIR))
        text = errorTryLoadText(page_name, DEFAULT_SQUID_ERROR_DIR);

    /* giving up if failed */
    if (!text)
        fatal("failed to find or read error text file.");

    return text;
}

static char *
errorTryLoadText(const char *page_name, const char *dir)
{
    int fd;
    char path[MAXPATHLEN];
    char buf[4096];
    char *text;
    ssize_t len;
    MemBuf textbuf;

    snprintf(path, sizeof(path), "%s/%s", dir, page_name);
    fd = file_open(path, O_RDONLY | O_TEXT);

    if (fd < 0) {
        debugs(4, 0, "errorTryLoadText: '" << path << "': " << xstrerror());
        return NULL;
    }

    textbuf.init();

    while((len = FD_READ_METHOD(fd, buf, sizeof(buf))) > 0) {
        textbuf.append(buf, len);
    }

    if (len < 0) {
        debugs(4, 0, "errorTryLoadText: failed to fully read: '" << path << "': " << xstrerror());
    }

    file_close(fd);

    if (strstr(textbuf.buf, "%s") == NULL)
        textbuf.append("%S", 2);	/* add signature */

    /* Shrink memory size down to exact size. MemBuf has a tencendy
     * to be rather large..
     */
    text = xstrdup(textbuf.buf);

    textbuf.clean();

    return text;
}

static ErrorDynamicPageInfo *
errorDynamicPageInfoCreate(int id, const char *page_name)
{
    ErrorDynamicPageInfo *info = new ErrorDynamicPageInfo;
    info->id = id;
    info->page_name = xstrdup(page_name);
    return info;
}

static void
errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info)
{
    assert(info);
    xfree(info->page_name);
    delete info;
}

static int
errorPageId(const char *page_name)
{
    for (int i = 0; i < ERR_MAX; i++) {
        if (strcmp(err_type_str[i], page_name) == 0)
            return i;
    }

    for (size_t j = 0; j < ErrorDynamicPages.size(); j++) {
        if (strcmp(ErrorDynamicPages.items[j]->page_name, page_name) == 0)
            return j + ERR_MAX;
    }

    return ERR_NONE;
}

err_type
errorReservePageId(const char *page_name)
{
    ErrorDynamicPageInfo *info;
    int id = errorPageId(page_name);

    if (id == ERR_NONE) {
        info = errorDynamicPageInfoCreate(ERR_MAX + ErrorDynamicPages.size(), page_name);
        ErrorDynamicPages.push_back(info);
        id = info->id;
    }

    return (err_type)id;
}

static const char *
errorPageName(int pageId)
{
    if (pageId >= ERR_NONE && pageId < ERR_MAX)		/* common case */
        return err_type_str[pageId];

    if (pageId >= ERR_MAX && pageId - ERR_MAX < (ssize_t)ErrorDynamicPages.size())
        return ErrorDynamicPages.items[pageId - ERR_MAX]->page_name;

    return "ERR_UNKNOWN";	/* should not happen */
}

/*
 * Function:  errorCon
 *
 * Abstract:  This function creates a ErrorState object.
 */
ErrorState *
errorCon(err_type type, http_status status, HttpRequest * request)
{
    ErrorState *err = new ErrorState;
    err->page_id = type;	/* has to be reset manually if needed */
    err->type = type;
    err->httpStatus = status;

    if (request != NULL) {
        err->request = HTTPMSGLOCK(request);
        err->src_addr = request->client_addr;
    }

    return err;
}

/*
 * Function:  errorAppendEntry
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then stores the text in the specified store
 *            entry.  This function should only be called by ``server
 *            side routines'' which need to communicate errors to the
 *            client side.  It should also be called from client_side.c
 *            because we now support persistent connections, and
 *            cannot assume that we can immediately write to the socket
 *            for an error.
 */
void
errorAppendEntry(StoreEntry * entry, ErrorState * err)
{
    HttpReply *rep;
    assert(entry->mem_obj != NULL);
    assert (entry->isEmpty());
    debugs(4, 4, "Creating an error page for entry " << entry <<
           " with errorstate " << err <<
           " page id " << err->page_id);

    if (entry->store_status != STORE_PENDING) {
        debugs(4, 2, "Skipping error page due to store_status: " << entry->store_status);
        /*
         * If the entry is not STORE_PENDING, then no clients
         * care about it, and we don't need to generate an
         * error message
         */
        assert(EBIT_TEST(entry->flags, ENTRY_ABORTED));
        assert(entry->mem_obj->nclients == 0);
        errorStateFree(err);
        return;
    }

    if (err->page_id == TCP_RESET) {
        if (err->request) {
            debugs(4, 2, "RSTing this reply");
            err->request->flags.setResetTCP();
        }
    }

    entry->lock();
    entry->buffer();
    rep = errorBuildReply(err);
    /* Add authentication header */
    /* TODO: alter errorstate to be accel on|off aware. The 0 on the next line
     * depends on authenticate behaviour: all schemes to date send no extra
     * data on 407/401 responses, and do not check the accel state on 401/407
     * responses 
     */
    authenticateFixHeader(rep, err->auth_user_request, err->request, 0, 1);
    entry->replaceHttpReply(rep);
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->flush();
    entry->complete();
    entry->negativeCache();
    entry->releaseRequest();
    entry->unlock();
    errorStateFree(err);
}

/*
 * Function:  errorSend
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then sends it to the client.
 *            The callback function errorSendComplete() is called after
 *            the page has been written to the client socket (fd).
 *            errorSendComplete() deallocates 'err'.  We need to add
 *            'err' to the cbdata because comm_write() requires it
 *            for all callback data pointers.
 *
 *            Note, normally errorSend() should only be called from
 *            routines in ssl.c and pass.c, where we don't have any
 *            StoreEntry's.  In client_side.c we must allocate a StoreEntry
 *            for errors and use errorAppendEntry() to account for
 *            persistent/pipeline connections.
 */
void
errorSend(int fd, ErrorState * err)
{
    HttpReply *rep;
    debugs(4, 3, "errorSend: FD " << fd << ", err=" << err);
    assert(fd >= 0);
    /*
     * ugh, this is how we make sure error codes get back to
     * the client side for logging and error tracking.
     */

    if (err->request)
        err->request->errType = err->type;

    /* moved in front of errorBuildBuf @?@ */
    err->flags.flag_cbdata = 1;

    rep = errorBuildReply(err);

    comm_write_mbuf(fd, rep->pack(), errorSendComplete, err);

    delete rep;
}

/*
 * Function:  errorSendComplete
 *
 * Abstract:  Called by commHandleWrite() after data has been written
 *            to the client socket.
 *
 * Note:      If there is a callback, the callback is responsible for
 *            closeing the FD, otherwise we do it ourseves.
 */
static void
errorSendComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    ErrorState *err = static_cast<ErrorState *>(data);
    debugs(4, 3, "errorSendComplete: FD " << fd << ", size=" << size);

    if (errflag != COMM_ERR_CLOSING) {
        if (err->callback) {
            debugs(4, 3, "errorSendComplete: callback");
            err->callback(fd, err->callback_data, size);
        } else {
            comm_close(fd);
            debugs(4, 3, "errorSendComplete: comm_close");
        }
    }

    errorStateFree(err);
}

void
errorStateFree(ErrorState * err)
{
    HTTPMSGUNLOCK(err->request);
    safe_free(err->redirect_url);
    safe_free(err->url);
    safe_free(err->dnsserver_msg);
    safe_free(err->request_hdrs);
    wordlistDestroy(&err->ftp.server_msg);
    safe_free(err->ftp.request);
    safe_free(err->ftp.reply);
    AUTHUSERREQUESTUNLOCK(err->auth_user_request, "errstate");
    safe_free(err->err_msg);
    cbdataFree(err);
}

static int
errorDump(ErrorState * err, MemBuf * mb)
{
    HttpRequest *r = err->request;
    MemBuf str;
    const char *p = NULL;	/* takes priority over mb if set */
    str.reset();
    /* email subject line */
    str.Printf("CacheErrorInfo - %s", errorPageName(err->type));
    mb->Printf("?subject=%s", rfc1738_escape_part(str.buf));
    str.reset();
    /* email body */
    str.Printf("CacheHost: %s\r\n", getMyHostname());
    /* - Err Msgs */
    str.Printf("ErrPage: %s\r\n", errorPageName(err->type));

    if (err->xerrno) {
        str.Printf("Err: (%d) %s\r\n", err->xerrno, strerror(err->xerrno));
    } else {
        str.Printf("Err: [none]\r\n");
    }

    if (err->auth_user_request->denyMessage())
        str.Printf("Auth ErrMsg: %s\r\n", err->auth_user_request->denyMessage());

    if (err->dnsserver_msg) {
        str.Printf("DNS Server ErrMsg: %s\r\n", err->dnsserver_msg);
    }

    /* - TimeStamp */
    str.Printf("TimeStamp: %s\r\n\r\n", mkrfc1123(squid_curtime));

    /* - IP stuff */
    str.Printf("ClientIP: %s\r\n", inet_ntoa(err->src_addr));

    if (r && r->hier.host) {
        str.Printf("ServerIP: %s\r\n", r->hier.host);
    }

    str.Printf("\r\n");
    /* - HTTP stuff */
    str.Printf("HTTP Request:\r\n");

    if (NULL != r) {
        Packer p;
        str.Printf("%s %s HTTP/%d.%d\n",
                   RequestMethodStr[r->method],
                   r->urlpath.size() ? r->urlpath.buf() : "/",
                   r->http_ver.major, r->http_ver.minor);
        packerToMemInit(&p, &str);
        r->header.packInto(&p);
        packerClean(&p);
    } else if (err->request_hdrs) {
        p = err->request_hdrs;
    } else {
        p = "[none]";
    }

    str.Printf("\r\n");
    /* - FTP stuff */

    if (err->ftp.request) {
        str.Printf("FTP Request: %s\r\n", err->ftp.request);
        str.Printf("FTP Reply: %s\r\n", err->ftp.reply);
        str.Printf("FTP Msg: ");
        wordlistCat(err->ftp.server_msg, &str);
        str.Printf("\r\n");
    }

    str.Printf("\r\n");
    mb->Printf("&body=%s", rfc1738_escape_part(str.buf));
    str.clean();
    return 0;
}

#define CVT_BUF_SZ 512

/*
 * a - User identity                            x
 * B - URL with FTP %2f hack                    x
 * c - Squid error code                         x
 * d - seconds elapsed since request received   x
 * e - errno                                    x
 * E - strerror()                               x
 * f - FTP request line                         x
 * F - FTP reply line                           x
 * g - FTP server message                       x
 * h - cache hostname                           x
 * H - server host name                         x
 * i - client IP address                        x
 * I - server IP address                        x
 * L - HREF link for more info/contact          x
 * M - Request Method                           x
 * m - Error message returned by auth helper    x 
 * o - Message returned external acl helper     x
 * p - URL port #                               x
 * P - Protocol                                 x
 * R - Full HTTP Request                        x
 * S - squid signature from ERR_SIGNATURE       x
 * s - caching proxy software with version      x
 * t - local time                               x
 * T - UTC                                      x
 * U - URL without password                     x
 * u - URL with password                        x
 * w - cachemgr email address                   x
 * W - error data (to be included in the mailto links)
 * z - dns server error message                 x
 * Z - Preformatted error message               x
 */

static const char *
errorConvert(char token, ErrorState * err)
{
    HttpRequest *r = err->request;
    static MemBuf mb;
    const char *p = NULL;	/* takes priority over mb if set */
    int do_quote = 1;

    mb.reset();

    switch (token) {

    case 'a':

        if (r && r->auth_user_request)
            p = r->auth_user_request->username();

        if (!p)
            p = "-";

        break;

    case 'B':
        p = r ? ftpUrlWith2f(r) : "[no URL]";

        break;

    case 'c':
        p = errorPageName(err->type);

        break;

    case 'e':
        mb.Printf("%d", err->xerrno);

        break;

    case 'E':

        if (err->xerrno)
            mb.Printf("(%d) %s", err->xerrno, strerror(err->xerrno));
        else
            mb.Printf("[No Error]");

        break;

    case 'f':
        /* FTP REQUEST LINE */
        if (err->ftp.request)
            p = err->ftp.request;
        else
            p = "nothing";

        break;

    case 'F':
        /* FTP REPLY LINE */
        if (err->ftp.request)
            p = err->ftp.reply;
        else
            p = "nothing";

        break;

    case 'g':
        /* FTP SERVER MESSAGE */
        wordlistCat(err->ftp.server_msg, &mb);

        break;

    case 'h':
        mb.Printf("%s", getMyHostname());

        break;

    case 'H':
        if (r) {
            if (r->hier.host)
                p = r->hier.host;
            else
                p = r->host;
        } else
            p = "[unknown host]";

        break;

    case 'i':
        mb.Printf("%s", inet_ntoa(err->src_addr));

        break;

    case 'I':
        if (r && r->hier.host) {
            mb.Printf("%s", r->hier.host);
        } else
            p = "[unknown]";

        break;

    case 'L':
        if (Config.errHtmlText) {
            mb.Printf("%s", Config.errHtmlText);
            do_quote = 0;
        } else
            p = "[not available]";

        break;

    case 'm':
        p = err->auth_user_request->denyMessage("[not available]");

        break;

    case 'M':
        p = r ? RequestMethodStr[r->method] : "[unknown method]";

        break;

    case 'o':
        p = external_acl_message ? external_acl_message : "[not available]";

        break;

    case 'p':
        if (r) {
            mb.Printf("%d", (int) r->port);
        } else {
            p = "[unknown port]";
        }

        break;

    case 'P':
        p = r ? ProtocolStr[r->protocol] : "[unknown protocol]";
        break;

    case 'R':

        if (NULL != r) {
            Packer p;
            mb.Printf("%s %s HTTP/%d.%d\n",
                      RequestMethodStr[r->method],
                      r->urlpath.size() ? r->urlpath.buf() : "/",
                      r->http_ver.major, r->http_ver.minor);
            packerToMemInit(&p, &mb);
            r->header.packInto(&p);
            packerClean(&p);
        } else if (err->request_hdrs) {
            p = err->request_hdrs;
        } else {
            p = "[no request]";
        }

        break;

    case 's':
        p = visible_appname_string;
        break;

    case 'S':
        /* signature may contain %-escapes, recursion */

        if (err->page_id != ERR_SQUID_SIGNATURE) {
            const int saved_id = err->page_id;
            err->page_id = ERR_SQUID_SIGNATURE;
            MemBuf *sign_mb = errorBuildContent(err);
            mb.Printf("%s", sign_mb->content());
            sign_mb->clean();
            delete sign_mb;
            err->page_id = saved_id;
            do_quote = 0;
        } else {
            /* wow, somebody put %S into ERR_SIGNATURE, stop recursion */
            p = "[%S]";
        }

        break;

    case 't':
        mb.Printf("%s", mkhttpdlogtime(&squid_curtime));
        break;

    case 'T':
        mb.Printf("%s", mkrfc1123(squid_curtime));
        break;

    case 'U':
        p = r ? urlCanonicalClean(r) : err->url ? err->url : "[no URL]";
        break;

    case 'u':
        p = r ? urlCanonical(r) : err->url ? err->url : "[no URL]";
        break;

    case 'w':

        if (Config.adminEmail)
            mb.Printf("%s", Config.adminEmail);
        else
            p = "[unknown]";

        break;

    case 'W':
        if (Config.adminEmail && Config.onoff.emailErrData)
            errorDump(err, &mb);

        break;

    case 'z':
        if (err->dnsserver_msg)
            p = err->dnsserver_msg;
        else
            p = "[unknown]";

        break;

    case 'Z':
        if (err->err_msg)
            p = err->err_msg;
        else
            p = "[unknown]";

        break;

    case '%':
        p = "%";

        break;

    default:
        mb.Printf("%%%c", token);

        do_quote = 0;

        break;
    }

    if (!p)
        p = mb.buf;		/* do not use mb after this assignment! */

    assert(p);

    debugs(4, 3, "errorConvert: %%" << token << " --> '" << p << "'" );

    if (do_quote)
        p = html_quote(p);

    return p;
}

/* allocates and initializes an error response */
HttpReply *
errorBuildReply(ErrorState * err)
{
    HttpReply *rep = new HttpReply;
    const char *name = errorPageName(err->page_id);
    /* no LMT for error pages; error pages expire immediately */
    HttpVersion version(1, 0);

    if (strchr(name, ':')) {
        /* Redirection */
        rep->setHeaders(version, HTTP_MOVED_TEMPORARILY, NULL, "text/html", 0, 0, squid_curtime);

        if (err->request) {
            char *quoted_url = rfc1738_escape_part(urlCanonical(err->request));
            httpHeaderPutStrf(&rep->header, HDR_LOCATION, name, quoted_url);
        }

        httpHeaderPutStrf(&rep->header, HDR_X_SQUID_ERROR, "%d %s", err->httpStatus, "Access Denied");
    } else {
        MemBuf *content = errorBuildContent(err);
        rep->setHeaders(version, err->httpStatus, NULL, "text/html", content->contentSize(), 0, squid_curtime);
        /*
         * include some information for downstream caches. Implicit
         * replaceable content. This isn't quite sufficient. xerrno is not
         * necessarily meaningful to another system, so we really should
         * expand it. Additionally, we should identify ourselves. Someone
         * might want to know. Someone _will_ want to know OTOH, the first
         * X-CACHE-MISS entry should tell us who.
         */
        httpHeaderPutStrf(&rep->header, HDR_X_SQUID_ERROR, "%s %d",
                          name, err->xerrno);
        httpBodySet(&rep->body, content);
        /* do not memBufClean() or delete the content, it was absorbed by httpBody */
    }

    return rep;
}

static MemBuf *
errorBuildContent(ErrorState * err)
{
    MemBuf *content = new MemBuf;
    const char *m;
    const char *p;
    const char *t;
    assert(err != NULL);
    assert(err->page_id > ERR_NONE && err->page_id < error_page_count);
    content->init();
    m = error_text[err->page_id];
    assert(m);

    while ((p = strchr(m, '%'))) {
        content->append(m, p - m);	/* copy */
        t = errorConvert(*++p, err);	/* convert */
        content->Printf("%s", t);	/* copy */
        m = p + 1;		/* advance */
    }

    if (*m)
        content->Printf("%s", m);	/* copy tail */

    assert((size_t)content->contentSize() == strlen(content->content()));

    return content;
}
