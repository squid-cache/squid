
/*
 * $Id$
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
#include "config.h"

#include "errorpage.h"
#include "auth/UserRequest.h"
#include "SquidTime.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "fde.h"
#include "MemBuf.h"
#include "rfc1738.h"
#include "URLScheme.h"
#include "wordlist.h"

/**
 \defgroup ErrorPageInternal Error Page Internals
 \ingroup ErrorPageAPI
 *
 \section Abstract Abstract:
 *   These routines are used to generate error messages to be
 *   sent to clients.  The error type is used to select between
 *   the various message formats. (formats are stored in the
 *   Config.errorDirectory)
 */


#ifndef DEFAULT_SQUID_ERROR_DIR
/** Where to look for errors if config path fails.
 \note Please use ./configure --datadir=/path instead of patching
 */
#define DEFAULT_SQUID_ERROR_DIR   DEFAULT_SQUID_DATA_DIR"/errors"
#endif

/// \ingroup ErrorPageInternal
CBDATA_CLASS_INIT(ErrorState);

/* local types */

/// \ingroup ErrorPageInternal
typedef struct {
    int id;
    char *page_name;
} ErrorDynamicPageInfo;

/* local constant and vars */

/**
 \ingroup ErrorPageInternal
 *
 \note  hard coded error messages are not appended with %S
 *      automagically to give you more control on the format
 */
static const struct {
    int type;			/* and page_id */
    const char *text;
}

error_hard_text[] = {

    {
        ERR_SQUID_SIGNATURE,
        "\n<br>\n"
        "<hr>\n"
        "<div id=\"footer\">\n"
        "Generated %T by %h (%s)\n"
        "</div>\n"
        "</body></html>\n"
    },
    {
        TCP_RESET,
        "reset"
    }
};

/// \ingroup ErrorPageInternal
static Vector<ErrorDynamicPageInfo *> ErrorDynamicPages;

/* local prototypes */

/// \ingroup ErrorPageInternal
static const int error_hard_text_count = sizeof(error_hard_text) / sizeof(*error_hard_text);

/// \ingroup ErrorPageInternal
static char **error_text = NULL;

/// \ingroup ErrorPageInternal
static int error_page_count = 0;

/// \ingroup ErrorPageInternal
static MemBuf error_stylesheet;

static char *errorTryLoadText(const char *page_name, const char *dir, bool silent = false);
static char *errorLoadText(const char *page_name);
static const char *errorFindHardText(err_type type);
static ErrorDynamicPageInfo *errorDynamicPageInfoCreate(int id, const char *page_name);
static void errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info);
static IOCB errorSendComplete;


/// \ingroup ErrorPageInternal
err_type &operator++ (err_type &anErr)
{
    int tmp = (int)anErr;
    anErr = (err_type)(++tmp);
    return anErr;
}

/// \ingroup ErrorPageInternal
int operator - (err_type const &anErr, err_type const &anErr2)
{
    return (int)anErr - (int)anErr2;
}

void
errorInitialize(void)
{
    err_type i;
    const char *text;
    error_page_count = ERR_MAX + ErrorDynamicPages.size();
    error_text = static_cast<char **>(xcalloc(error_page_count, sizeof(char *)));

    for (i = ERR_NONE, ++i; i < error_page_count; ++i) {
        safe_free(error_text[i]);

        if ((text = errorFindHardText(i))) {
            /**\par
             * Index any hard-coded error text into defaults.
             */
            error_text[i] = xstrdup(text);

        } else if (i < ERR_MAX) {
            /**\par
             * Index precompiled fixed template files from one of two sources:
             *  (a) default language translation directory (error_default_language)
             *  (b) admin specified custom directory (error_directory)
             */
            error_text[i] = errorLoadText(err_type_str[i]);

        } else {
            /** \par
             * Index any unknown file names used by deny_info.
             */
            ErrorDynamicPageInfo *info = ErrorDynamicPages.items[i - ERR_MAX];
            assert(info && info->id == i && info->page_name);

            if (strchr(info->page_name, ':') == NULL) {
                /** But only if they are not redirection URL. */
                error_text[i] = errorLoadText(info->page_name);
            }
        }
    }

    error_stylesheet.reset();

    // look for and load stylesheet into global MemBuf for it.
    if (Config.errorStylesheet) {
        char *temp = errorTryLoadText(Config.errorStylesheet,NULL);
        if (temp) {
            error_stylesheet.Printf("%s",temp);
            safe_free(temp);
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

/// \ingroup ErrorPageInternal
static const char *
errorFindHardText(err_type type)
{
    int i;

    for (i = 0; i < error_hard_text_count; i++)
        if (error_hard_text[i].type == type)
            return error_hard_text[i].text;

    return NULL;
}

/**
 * \ingroup ErrorPageInternal
 *
 * Load into the in-memory error text Index a file probably available at:
 *  (a) admin specified custom directory (error_directory)
 *  (b) default language translation directory (error_default_language)
 *  (c) English sub-directory where errors should ALWAYS exist
 */
static char *
errorLoadText(const char *page_name)
{
    char *text = NULL;

    /** test error_directory configured location */
    if (Config.errorDirectory)
        text = errorTryLoadText(page_name, Config.errorDirectory);

#if USE_ERR_LOCALES
    /** test error_default_language location */
    if (!text && Config.errorDefaultLanguage) {
        char dir[256];
        snprintf(dir,256,"%s/%s", DEFAULT_SQUID_ERROR_DIR, Config.errorDefaultLanguage);
        text = errorTryLoadText(page_name, dir);
        if (!text) {
            debugs(1, DBG_CRITICAL, "Unable to load default error language files. Reset to backups.");
        }
    }
#endif

    /* test default location if failed (templates == English translation base templates) */
    if (!text) {
        text = errorTryLoadText(page_name, DEFAULT_SQUID_ERROR_DIR"/templates");
    }

    /* giving up if failed */
    if (!text)
        fatal("failed to find or read error text file.");

    return text;
}

/// \ingroup ErrorPageInternal
static char *
errorTryLoadText(const char *page_name, const char *dir, bool silent)
{
    int fd;
    char path[MAXPATHLEN];
    char buf[4096];
    char *text;
    ssize_t len;
    MemBuf textbuf;

    // maybe received compound parts, maybe an absolute page_name and no dir
    if (dir)
        snprintf(path, sizeof(path), "%s/%s", dir, page_name);
    else
        snprintf(path, sizeof(path), "%s", page_name);

    fd = file_open(path, O_RDONLY | O_TEXT);

    if (fd < 0) {
        /* with dynamic locale negotiation we may see some failures before a success. */
        if (!silent)
            debugs(4, DBG_CRITICAL, HERE << "'" << path << "': " << xstrerror());
        return NULL;
    }

    textbuf.init();

    while ((len = FD_READ_METHOD(fd, buf, sizeof(buf))) > 0) {
        textbuf.append(buf, len);
    }

    if (len < 0) {
        debugs(4, DBG_CRITICAL, HERE << "failed to fully read: '" << path << "': " << xstrerror());
    }

    file_close(fd);

    /* Shrink memory size down to exact size. MemBuf has a tencendy
     * to be rather large..
     */
    text = xstrdup(textbuf.buf);

    textbuf.clean();

    return text;
}

/// \ingroup ErrorPageInternal
static ErrorDynamicPageInfo *
errorDynamicPageInfoCreate(int id, const char *page_name)
{
    ErrorDynamicPageInfo *info = new ErrorDynamicPageInfo;
    info->id = id;
    info->page_name = xstrdup(page_name);
    return info;
}

/// \ingroup ErrorPageInternal
static void
errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info)
{
    assert(info);
    safe_free(info->page_name);
    delete info;
}

/// \ingroup ErrorPageInternal
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

/// \ingroup ErrorPageInternal
static const char *
errorPageName(int pageId)
{
    if (pageId >= ERR_NONE && pageId < ERR_MAX)		/* common case */
        return err_type_str[pageId];

    if (pageId >= ERR_MAX && pageId - ERR_MAX < (ssize_t)ErrorDynamicPages.size())
        return ErrorDynamicPages.items[pageId - ERR_MAX]->page_name;

    return "ERR_UNKNOWN";	/* should not happen */
}

ErrorState *
errorCon(err_type type, http_status status, HttpRequest * request)
{
    ErrorState *err = new ErrorState;
    err->page_id = type;	/* has to be reset manually if needed */
    err->err_language = NULL;
    err->type = type;
    err->httpStatus = status;

    if (request != NULL) {
        err->request = HTTPMSGLOCK(request);
        err->src_addr = request->client_addr;
    }

    return err;
}

void
errorAppendEntry(StoreEntry * entry, ErrorState * err)
{
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
    entry->replaceHttpReply( err->BuildHttpReply() );
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->flush();
    entry->complete();
    entry->negativeCache();
    entry->releaseRequest();
    entry->unlock();
    errorStateFree(err);
}

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

    rep = err->BuildHttpReply();

    comm_write_mbuf(fd, rep->pack(), errorSendComplete, err);

    delete rep;
}

/**
 \ingroup ErrorPageAPI
 *
 * Called by commHandleWrite() after data has been written
 * to the client socket.
 *
 \note If there is a callback, the callback is responsible for
 *     closing the FD, otherwise we do it ourselves.
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
    safe_free(err->request_hdrs);
    wordlistDestroy(&err->ftp.server_msg);
    safe_free(err->ftp.request);
    safe_free(err->ftp.reply);
    AUTHUSERREQUESTUNLOCK(err->auth_user_request, "errstate");
    safe_free(err->err_msg);
#if USE_ERR_LOCALES
    if (err->err_language != Config.errorDefaultLanguage)
#endif
        safe_free(err->err_language);
    cbdataFree(err);
}

int
ErrorState::Dump(MemBuf * mb)
{
    MemBuf str;
    const char *p = NULL;	/* takes priority over mb if set */
    char ntoabuf[MAX_IPSTRLEN];

    str.reset();
    /* email subject line */
    str.Printf("CacheErrorInfo - %s", errorPageName(type));
    mb->Printf("?subject=%s", rfc1738_escape_part(str.buf));
    str.reset();
    /* email body */
    str.Printf("CacheHost: %s\r\n", getMyHostname());
    /* - Err Msgs */
    str.Printf("ErrPage: %s\r\n", errorPageName(type));

    if (xerrno) {
        str.Printf("Err: (%d) %s\r\n", xerrno, strerror(xerrno));
    } else {
        str.Printf("Err: [none]\r\n");
    }

    if (auth_user_request->denyMessage())
        str.Printf("Auth ErrMsg: %s\r\n", auth_user_request->denyMessage());

    if (dnsError.size() > 0)
        str.Printf("DNS ErrMsg: %s\r\n", dnsError.termedBuf());

    /* - TimeStamp */
    str.Printf("TimeStamp: %s\r\n\r\n", mkrfc1123(squid_curtime));

    /* - IP stuff */
    str.Printf("ClientIP: %s\r\n", src_addr.NtoA(ntoabuf,MAX_IPSTRLEN));

    if (request && request->hier.host[0] != '\0') {
        str.Printf("ServerIP: %s\r\n", request->hier.host);
    }

    str.Printf("\r\n");
    /* - HTTP stuff */
    str.Printf("HTTP Request:\r\n");

    if (NULL != request) {
        Packer pck;
        String urlpath_or_slash;

        if (request->urlpath.size() != 0)
            urlpath_or_slash = request->urlpath;
        else
            urlpath_or_slash = "/";

        str.Printf("%s " SQUIDSTRINGPH " HTTP/%d.%d\n",
                   RequestMethodStr(request->method),
                   SQUIDSTRINGPRINT(urlpath_or_slash),
                   request->http_ver.major, request->http_ver.minor);
        packerToMemInit(&pck, &str);
        request->header.packInto(&pck);
        packerClean(&pck);
    } else if (request_hdrs) {
        p = request_hdrs;
    } else {
        p = "[none]";
    }

    str.Printf("\r\n");
    /* - FTP stuff */

    if (ftp.request) {
        str.Printf("FTP Request: %s\r\n", ftp.request);
        str.Printf("FTP Reply: %s\r\n", ftp.reply);
        str.Printf("FTP Msg: ");
        wordlistCat(ftp.server_msg, &str);
        str.Printf("\r\n");
    }

    str.Printf("\r\n");
    mb->Printf("&body=%s", rfc1738_escape_part(str.buf));
    str.clean();
    return 0;
}

/// \ingroup ErrorPageInternal
#define CVT_BUF_SZ 512

const char *
ErrorState::Convert(char token)
{
    static MemBuf mb;
    const char *p = NULL;	/* takes priority over mb if set */
    int do_quote = 1;
    char ntoabuf[MAX_IPSTRLEN];

    mb.reset();

    switch (token) {

    case 'a':

        if (request && request->auth_user_request)
            p = request->auth_user_request->username();

        if (!p)
            p = "-";

        break;

    case 'B':
        p = request ? ftpUrlWith2f(request) : "[no URL]";

        break;

    case 'c':
        p = errorPageName(type);

        break;

    case 'e':
        mb.Printf("%d", xerrno);

        break;

    case 'E':

        if (xerrno)
            mb.Printf("(%d) %s", xerrno, strerror(xerrno));
        else
            mb.Printf("[No Error]");

        break;

    case 'f':
        /* FTP REQUEST LINE */
        if (ftp.request)
            p = ftp.request;
        else
            p = "nothing";

        break;

    case 'F':
        /* FTP REPLY LINE */
        if (ftp.request)
            p = ftp.reply;
        else
            p = "nothing";

        break;

    case 'g':
        /* FTP SERVER MESSAGE */
        wordlistCat(ftp.server_msg, &mb);

        break;

    case 'h':
        mb.Printf("%s", getMyHostname());
        break;

    case 'H':
        if (request) {
            if (request->hier.host[0] != '\0') // if non-empty string.
                p = request->hier.host;
            else
                p = request->GetHost();
        } else
            p = "[unknown host]";

        break;

    case 'i':
        mb.Printf("%s", src_addr.NtoA(ntoabuf,MAX_IPSTRLEN));

        break;

    case 'I':
        if (request && request->hier.host[0] != '\0') // if non-empty string
            mb.Printf("%s", request->hier.host);
        else
            p = "[unknown]";

        break;

    case 'l':
        mb.append(error_stylesheet.content(), error_stylesheet.contentSize());
        do_quote = 0;
        break;

    case 'L':
        if (Config.errHtmlText) {
            mb.Printf("%s", Config.errHtmlText);
            do_quote = 0;
        } else
            p = "[not available]";

        break;

    case 'm':
        p = auth_user_request->denyMessage("[not available]");

        break;

    case 'M':
        p = request ? RequestMethodStr(request->method) : "[unknown method]";

        break;

    case 'o':
        p = request ? request->extacl_message.termedBuf() : external_acl_message;
        if (!p)
            p = "[not available]";
        break;

    case 'p':
        if (request) {
            mb.Printf("%d", (int) request->port);
        } else {
            p = "[unknown port]";
        }

        break;

    case 'P':
        p = request ? ProtocolStr[request->protocol] : "[unknown protocol]";
        break;

    case 'R':

        if (NULL != request) {
            Packer pck;
            String urlpath_or_slash;

            if (request->urlpath.size() != 0)
                urlpath_or_slash = request->urlpath;
            else
                urlpath_or_slash = "/";

            mb.Printf("%s " SQUIDSTRINGPH " HTTP/%d.%d\n",
                      RequestMethodStr(request->method),
                      SQUIDSTRINGPRINT(urlpath_or_slash),
                      request->http_ver.major, request->http_ver.minor);
            packerToMemInit(&pck, &mb);
            request->header.packInto(&pck);
            packerClean(&pck);
        } else if (request_hdrs) {
            p = request_hdrs;
        } else {
            p = "[no request]";
        }

        break;

    case 's':
        p = visible_appname_string;
        break;

    case 'S':
        /* signature may contain %-escapes, recursion */

        if (page_id != ERR_SQUID_SIGNATURE) {
            const int saved_id = page_id;
            page_id = ERR_SQUID_SIGNATURE;
            MemBuf *sign_mb = BuildContent();
            mb.Printf("%s", sign_mb->content());
            sign_mb->clean();
            delete sign_mb;
            page_id = saved_id;
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
        /* Using the fake-https version of canonical so error pages see https:// */
        /* even when the url-path cannot be shown as more than '*' */
        p = request ? urlCanonicalFakeHttps(request) : url ? url : "[no URL]";
        break;

    case 'u':
        p = request ? urlCanonical(request) : url ? url : "[no URL]";
        break;

    case 'w':

        if (Config.adminEmail)
            mb.Printf("%s", Config.adminEmail);
        else
            p = "[unknown]";

        break;

    case 'W':
        if (Config.adminEmail && Config.onoff.emailErrData)
            Dump(&mb);

        break;

    case 'z':
        if (dnsError.size() > 0)
            p = dnsError.termedBuf();
        else
            p = "[unknown]";

        break;

    case 'Z':
        if (err_msg)
            p = err_msg;
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

HttpReply *
ErrorState::BuildHttpReply()
{
    HttpReply *rep = new HttpReply;
    const char *name = errorPageName(page_id);
    /* no LMT for error pages; error pages expire immediately */

    if (strchr(name, ':')) {
        /* Redirection */
        rep->setHeaders(HTTP_MOVED_TEMPORARILY, NULL, "text/html", 0, 0, -1);

        if (request) {
            char *quoted_url = rfc1738_escape_part(urlCanonical(request));
            httpHeaderPutStrf(&rep->header, HDR_LOCATION, name, quoted_url);
        }

        httpHeaderPutStrf(&rep->header, HDR_X_SQUID_ERROR, "%d %s", httpStatus, "Access Denied");
    } else {
        MemBuf *content = BuildContent();
        rep->setHeaders(httpStatus, NULL, "text/html", content->contentSize(), 0, -1);
        /*
         * include some information for downstream caches. Implicit
         * replaceable content. This isn't quite sufficient. xerrno is not
         * necessarily meaningful to another system, so we really should
         * expand it. Additionally, we should identify ourselves. Someone
         * might want to know. Someone _will_ want to know OTOH, the first
         * X-CACHE-MISS entry should tell us who.
         */
        httpHeaderPutStrf(&rep->header, HDR_X_SQUID_ERROR, "%s %d", name, xerrno);

#if USE_ERR_LOCALES
        /*
         * If error page auto-negotiate is enabled in any way, send the Vary.
         * RFC 2616 section 13.6 and 14.44 says MAY and SHOULD do this.
         * We have even better reasons though:
         * see http://wiki.squid-cache.org/KnowledgeBase/VaryNotCaching
         */
        if (!Config.errorDirectory) {
            /* We 'negotiated' this ONLY from the Accept-Language. */
            rep->header.delById(HDR_VARY);
            rep->header.putStr(HDR_VARY, "Accept-Language");
        }

        /* add the Content-Language header according to RFC section 14.12 */
        if (err_language) {
            rep->header.putStr(HDR_CONTENT_LANGUAGE, err_language);
        } else
#endif /* USE_ERROR_LOCALES */
        {
            /* default templates are in English */
            /* language is known unless error_directory override used */
            if (!Config.errorDirectory)
                rep->header.putStr(HDR_CONTENT_LANGUAGE, "en");
        }

        httpBodySet(&rep->body, content);
        /* do not memBufClean() or delete the content, it was absorbed by httpBody */
    }

    return rep;
}

MemBuf *
ErrorState::BuildContent()
{
    MemBuf *content = new MemBuf;
    const char *m = NULL;
    const char *p;
    const char *t;

    assert(page_id > ERR_NONE && page_id < error_page_count);

#if USE_ERR_LOCALES
    String hdr;
    char dir[256];
    int l = 0;

    /** error_directory option in squid.conf overrides translations.
     * Custom errors are always found either in error_directory or the templates directory.
     * Otherwise locate the Accept-Language header
     */
    if (!Config.errorDirectory && page_id < ERR_MAX && request && request->header.getList(HDR_ACCEPT_LANGUAGE, &hdr) ) {

        size_t pos = 0; // current parsing position in header string
        char *reset = NULL; // where to reset the p pointer for each new tag file
        char *dt = NULL;

        /* prep the directory path string to prevent snprintf ... */
        l = strlen(DEFAULT_SQUID_ERROR_DIR);
        memcpy(dir, DEFAULT_SQUID_ERROR_DIR, l);
        dir[ l++ ] = '/';
        reset = dt = dir + l;

        debugs(4, 6, HERE << "Testing Header: '" << hdr << "'");

        while ( pos < hdr.size() ) {

            /* skip any initial whitespace. */
            while (pos < hdr.size() && xisspace(hdr[pos])) pos++;

            /*
             * Header value format:
             *  - sequence of whitespace delimited tags
             *  - each tag may suffix with ';'.* which we can ignore.
             *  - IFF a tag contains only two characters we can wildcard ANY translations matching: <it> '-'? .*
             *    with preference given to an exact match.
             */
            bool invalid_byte = false;
            while (pos < hdr.size() && hdr[pos] != ';' && hdr[pos] != ',' && !xisspace(hdr[pos]) && dt < (dir+256) ) {
                if (!invalid_byte) {
#if HTTP_VIOLATIONS
                    // if accepting violations we may as well accept some broken browsers
                    //  which may send us the right code, wrong ISO formatting.
                    if (hdr[pos] == '_')
                        *dt = '-';
                    else
#endif
                        *dt = xtolower(hdr[pos]);
                    // valid codes only contain A-Z, hyphen (-) and *
                    if (*dt != '-' && *dt != '*' && (*dt < 'a' || *dt > 'z') )
                        invalid_byte = true;
                    else
                        dt++; // move to next destination byte.
                }
                pos++;
            }
            *dt++ = '\0'; // nul-terminated the filename content string before system use.

            debugs(4, 9, HERE << "STATE: dt='" << dt << "', reset='" << reset << "', pos=" << pos << ", buf='" << ((pos < hdr.size()) ? hdr.substr(pos,hdr.size()) : "") << "'");

            /* if we found anything we might use, try it. */
            if (*reset != '\0' && !invalid_byte) {

                /* wildcard uses the configured default language */
                if (reset[0] == '*' && reset[1] == '\0') {
                    debugs(4, 6, HERE << "Found language '" << reset << "'. Using configured default.");
                    m = error_text[page_id];
                    if (!Config.errorDirectory)
                        err_language = Config.errorDefaultLanguage;
                    break;
                }

                debugs(4, 6, HERE << "Found language '" << reset << "', testing for available template in: '" << dir << "'");

                m = errorTryLoadText( err_type_str[page_id], dir, false);

                if (m) {
                    /* store the language we found for the Content-Language reply header */
                    err_language = xstrdup(reset);
                    break;
                } else if (Config.errorLogMissingLanguages) {
                    debugs(4, DBG_IMPORTANT, "WARNING: Error Pages Missing Language: " << reset);
                }

#if HAVE_GLOB
                if ( (dt - reset) == 2) {
                    /* TODO glob the error directory for sub-dirs matching: <tag> '-*'   */
                    /* use first result. */
                    debugs(4,2, HERE << "wildcard fallback errors not coded yet.");
                }
#endif
            }

            dt = reset; // reset for next tag testing. we replace the failed name instead of cloning.

            // IFF we terminated the tag on whitespace or ';' we need to skip to the next ',' or end of header.
            while (pos < hdr.size() && hdr[pos] != ',') pos++;
            if (hdr[pos] == ',') pos++;
        }
    }
#endif /* USE_ERR_LOCALES */

    /** \par
     * If client-specific error templates are not enabled or available.
     * fall back to the old style squid.conf settings.
     */
    if (!m) {
        m = error_text[page_id];
#if USE_ERR_LOCALES
        if (!Config.errorDirectory)
            err_language = Config.errorDefaultLanguage;
#endif
        debugs(4, 2, HERE << "No existing error page language negotiated for " << errorPageName(page_id) << ". Using default error file.");
    }

    assert(m);
    content->init();

    while ((p = strchr(m, '%'))) {
        content->append(m, p - m);	/* copy */
        t = Convert(*++p);		/* convert */
        content->Printf("%s", t);	/* copy */
        m = p + 1;			/* advance */
    }

    if (*m)
        content->Printf("%s", m);	/* copy tail */

    assert((size_t)content->contentSize() == strlen(content->content()));

    return content;
}
