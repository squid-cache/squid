/*
 * DEBUG: section 04    Error Generation
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
#include "squid.h"
#include "cache_cf.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "disk.h"
#include "err_detail_type.h"
#include "errorpage.h"
#include "ftp.h"
#include "Store.h"
#include "html_quote.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "fde.h"
#include "MemBuf.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "URL.h"
#include "URLScheme.h"
#include "URL.h"
#include "tools.h"
#include "wordlist.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#include "SquidTime.h"
#if USE_SSL
#include "ssl/ErrorDetailManager.h"
#endif

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

#if !defined(DEFAULT_SQUID_ERROR_DIR)
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
    http_status page_redirect;
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

static const char *errorFindHardText(err_type type);
static ErrorDynamicPageInfo *errorDynamicPageInfoCreate(int id, const char *page_name);
static void errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info);
static IOCB errorSendComplete;

/// \ingroup ErrorPageInternal
/// manages an error page template
class ErrorPageFile: public TemplateFile
{
public:
    ErrorPageFile(const char *name, const err_type code): TemplateFile(name,code) { textBuf.init();}

    /// The template text data read from disk
    const char *text() { return textBuf.content(); }

private:
    /// stores the data read from disk to a local buffer
    virtual bool parse(const char *buf, int len, bool eof) {
        if (len)
            textBuf.append(buf, len);
        return true;
    }

    MemBuf textBuf; ///< A buffer to store the error page
};

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
            ErrorPageFile errTmpl(err_type_str[i], i);
            error_text[i] = errTmpl.loadDefault() ? xstrdup(errTmpl.text()) : NULL;
        } else {
            /** \par
             * Index any unknown file names used by deny_info.
             */
            ErrorDynamicPageInfo *info = ErrorDynamicPages.items[i - ERR_MAX];
            assert(info && info->id == i && info->page_name);

            const char *pg = info->page_name;
            if (info->page_redirect != HTTP_STATUS_NONE)
                pg = info->page_name +4;

            if (strchr(pg, ':') == NULL) {
                /** But only if they are not redirection URL. */
                ErrorPageFile errTmpl(pg, ERR_MAX);
                error_text[i] = errTmpl.loadDefault() ? xstrdup(errTmpl.text()) : NULL;
            }
        }
    }

    error_stylesheet.reset();

    // look for and load stylesheet into global MemBuf for it.
    if (Config.errorStylesheet) {
        ErrorPageFile tmpl("StylesSheet", ERR_MAX);
        tmpl.loadFromFile(Config.errorStylesheet);
        error_stylesheet.Printf("%s",tmpl.text());
    }

#if USE_SSL
    Ssl::errorDetailInitialize();
#endif
}

void
errorClean(void)
{
    if (error_text) {
        int i;

        for (i = ERR_NONE + 1; i < error_page_count; ++i)
            safe_free(error_text[i]);

        safe_free(error_text);
    }

    while (ErrorDynamicPages.size())
        errorDynamicPageInfoDestroy(ErrorDynamicPages.pop_back());

    error_page_count = 0;

#if USE_SSL
    Ssl::errorDetailClean();
#endif
}

/// \ingroup ErrorPageInternal
static const char *
errorFindHardText(err_type type)
{
    int i;

    for (i = 0; i < error_hard_text_count; ++i)
        if (error_hard_text[i].type == type)
            return error_hard_text[i].text;

    return NULL;
}

TemplateFile::TemplateFile(const char *name, const err_type code): silent(false), wasLoaded(false), templateName(name), templateCode(code)
{
    assert(name);
}

bool
TemplateFile::loadDefault()
{
    if (loaded()) // already loaded?
        return true;

    /** test error_directory configured location */
    if (Config.errorDirectory) {
        char path[MAXPATHLEN];
        snprintf(path, sizeof(path), "%s/%s", Config.errorDirectory, templateName.termedBuf());
        loadFromFile(path);
    }

#if USE_ERR_LOCALES
    /** test error_default_language location */
    if (!loaded() && Config.errorDefaultLanguage) {
        if (!tryLoadTemplate(Config.errorDefaultLanguage)) {
            debugs(1, (templateCode < TCP_RESET ? DBG_CRITICAL : 3), "Unable to load default error language files. Reset to backups.");
        }
    }
#endif

    /* test default location if failed (templates == English translation base templates) */
    if (!loaded()) {
        tryLoadTemplate("templates");
    }

    /* giving up if failed */
    if (!loaded()) {
        debugs(1, (templateCode < TCP_RESET ? DBG_CRITICAL : 3), "WARNING: failed to find or read error text file " << templateName);
        parse("Internal Error: Missing Template ", 33, '\0');
        parse(templateName.termedBuf(), templateName.size(), '\0');
    }

    return true;
}

bool
TemplateFile::tryLoadTemplate(const char *lang)
{
    assert(lang);

    char path[MAXPATHLEN];
    /* TODO: prep the directory path string to prevent snprintf ... */
    snprintf(path, sizeof(path), "%s/%s/%s",
             DEFAULT_SQUID_ERROR_DIR, lang, templateName.termedBuf());
    path[MAXPATHLEN-1] = '\0';

    if (loadFromFile(path))
        return true;

#if HAVE_GLOB
    if ( strlen(lang) == 2) {
        /* TODO glob the error directory for sub-dirs matching: <tag> '-*'   */
        /* use first result. */
        debugs(4,2, HERE << "wildcard fallback errors not coded yet.");
    }
#endif

    return false;
}

bool
TemplateFile::loadFromFile(const char *path)
{
    int fd;
    char buf[4096];
    ssize_t len;

    if (loaded()) // already loaded?
        return true;

    fd = file_open(path, O_RDONLY | O_TEXT);

    if (fd < 0) {
        /* with dynamic locale negotiation we may see some failures before a success. */
        if (!silent && templateCode < TCP_RESET)
            debugs(4, DBG_CRITICAL, HERE << "'" << path << "': " << xstrerror());
        wasLoaded = false;
        return wasLoaded;
    }

    while ((len = FD_READ_METHOD(fd, buf, sizeof(buf))) > 0) {
        if (!parse(buf, len, false)) {
            debugs(4, DBG_CRITICAL, HERE << " parse error while reading template file: " << path);
            wasLoaded = false;
            return wasLoaded;
        }
    }
    parse(buf, 0, true);

    if (len < 0) {
        debugs(4, DBG_CRITICAL, HERE << "failed to fully read: '" << path << "': " << xstrerror());
    }

    file_close(fd);

    wasLoaded = true;
    return wasLoaded;
}

bool strHdrAcptLangGetItem(const String &hdr, char *lang, int langLen, size_t &pos)
{
    while (pos < hdr.size()) {
        char *dt = lang;

        /* skip any initial whitespace. */
        while (pos < hdr.size() && xisspace(hdr[pos]))
            ++pos;

        /*
         * Header value format:
         *  - sequence of whitespace delimited tags
         *  - each tag may suffix with ';'.* which we can ignore.
         *  - IFF a tag contains only two characters we can wildcard ANY translations matching: <it> '-'? .*
         *    with preference given to an exact match.
         */
        bool invalid_byte = false;
        while (pos < hdr.size() && hdr[pos] != ';' && hdr[pos] != ',' && !xisspace(hdr[pos]) && dt < (lang + (langLen -1)) ) {
            if (!invalid_byte) {
#if USE_HTTP_VIOLATIONS
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
                    ++dt; // move to next destination byte.
            }
            ++pos;
        }
        *dt = '\0'; // nul-terminated the filename content string before system use.
        ++dt;

        // if we terminated the tag on garbage or ';' we need to skip to the next ',' or end of header.
        while (pos < hdr.size() && hdr[pos] != ',')
            ++pos;

        if (pos < hdr.size() && hdr[pos] == ',')
            ++pos;

        debugs(4, 9, HERE << "STATE: dt='" << dt << "', lang='" << lang << "', pos=" << pos << ", buf='" << ((pos < hdr.size()) ? hdr.substr(pos,hdr.size()) : "") << "'");

        /* if we found anything we might use, try it. */
        if (*lang != '\0' && !invalid_byte)
            return true;
    }
    return false;
}

bool
TemplateFile::loadFor(HttpRequest *request)
{
    String hdr;

#if USE_ERR_LOCALES
    if (loaded()) // already loaded?
        return true;

    if (!request || !request->header.getList(HDR_ACCEPT_LANGUAGE, &hdr) )
        return false;

    char lang[256];
    size_t pos = 0; // current parsing position in header string

    debugs(4, 6, HERE << "Testing Header: '" << hdr << "'");

    while ( strHdrAcptLangGetItem(hdr, lang, 256, pos) ) {

        /* wildcard uses the configured default language */
        if (lang[0] == '*' && lang[1] == '\0') {
            debugs(4, 6, HERE << "Found language '" << lang << "'. Using configured default.");
            return false;
        }

        debugs(4, 6, HERE << "Found language '" << lang << "', testing for available template");

        if (tryLoadTemplate(lang)) {
            /* store the language we found for the Content-Language reply header */
            errLanguage = lang;
            break;
        } else if (Config.errorLogMissingLanguages) {
            debugs(4, DBG_IMPORTANT, "WARNING: Error Pages Missing Language: " << lang);
        }
    }
#endif

    return loaded();
}

/// \ingroup ErrorPageInternal
static ErrorDynamicPageInfo *
errorDynamicPageInfoCreate(int id, const char *page_name)
{
    ErrorDynamicPageInfo *info = new ErrorDynamicPageInfo;
    info->id = id;
    info->page_name = xstrdup(page_name);
    info->page_redirect = static_cast<http_status>(atoi(page_name));

    /* WARNING on redirection status:
     * 2xx are permitted, but not documented officially.
     * - might be useful for serving static files (PAC etc) in special cases
     * 3xx require a URL suitable for Location: header.
     * - the current design does not allow for a Location: URI as well as a local file template
     *   although this possibility is explicitly permitted in the specs.
     * 4xx-5xx require a local file template.
     * - sending Location: on these codes with no body is invalid by the specs.
     * - current result is Squid crashing or XSS problems as dynamic deny_info load random disk files.
     * - a future redesign of the file loading may result in loading remote objects sent inline as local body.
     */
    if (info->page_redirect == HTTP_STATUS_NONE)
        ; // special case okay.
    else if (info->page_redirect < 200 || info->page_redirect > 599) {
        // out of range
        debugs(0, DBG_CRITICAL, "FATAL: status " << info->page_redirect << " is not valid on '" << page_name << "'");
        self_destruct();
    } else if ( /* >= 200 && */ info->page_redirect < 300 && strchr(&(page_name[4]), ':')) {
        // 2xx require a local template file
        debugs(0, DBG_CRITICAL, "FATAL: status " << info->page_redirect << " requires a template on '" << page_name << "'");
        self_destruct();
    } else if (info->page_redirect >= 300 && info->page_redirect <= 399 && !strchr(&(page_name[4]), ':')) {
        // 3xx require an absolute URL
        debugs(0, DBG_CRITICAL, "FATAL: status " << info->page_redirect << " requires a URL on '" << page_name << "'");
        self_destruct();
    } else if (info->page_redirect >= 400 /* && <= 599 */ && strchr(&(page_name[4]), ':')) {
        // 4xx/5xx require a local template file
        debugs(0, DBG_CRITICAL, "FATAL: status " << info->page_redirect << " requires a template on '" << page_name << "'");
        self_destruct();
    }
    // else okay.

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
    for (int i = 0; i < ERR_MAX; ++i) {
        if (strcmp(err_type_str[i], page_name) == 0)
            return i;
    }

    for (size_t j = 0; j < ErrorDynamicPages.size(); ++j) {
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
const char *
errorPageName(int pageId)
{
    if (pageId >= ERR_NONE && pageId < ERR_MAX)		/* common case */
        return err_type_str[pageId];

    if (pageId >= ERR_MAX && pageId - ERR_MAX < (ssize_t)ErrorDynamicPages.size())
        return ErrorDynamicPages.items[pageId - ERR_MAX]->page_name;

    return "ERR_UNKNOWN";	/* should not happen */
}

ErrorState::ErrorState(err_type t, http_status status, HttpRequest * req) :
        type(t),
        page_id(t),
        err_language(NULL),
        httpStatus(status),
#if USE_AUTH
        auth_user_request (NULL),
#endif
        request(NULL),
        url(NULL),
        xerrno(0),
        port(0),
        dnsError(),
        ttl(0),
        src_addr(),
        redirect_url(NULL),
        callback(NULL),
        callback_data(NULL),
        request_hdrs(NULL),
        err_msg(NULL),
#if USE_SSL
        detail(NULL),
#endif
        detailCode(ERR_DETAIL_NONE)
{
    memset(&flags, 0, sizeof(flags));
    memset(&ftp, 0, sizeof(ftp));

    if (page_id >= ERR_MAX && ErrorDynamicPages.items[page_id - ERR_MAX]->page_redirect != HTTP_STATUS_NONE)
        httpStatus = ErrorDynamicPages.items[page_id - ERR_MAX]->page_redirect;

    if (req != NULL) {
        request = HTTPMSGLOCK(req);
        src_addr = req->client_addr;
    }
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
        delete err;
        return;
    }

    if (err->page_id == TCP_RESET) {
        if (err->request) {
            debugs(4, 2, "RSTing this reply");
            err->request->flags.resetTcp=true;
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
    delete err;
}

void
errorSend(const Comm::ConnectionPointer &conn, ErrorState * err)
{
    HttpReply *rep;
    debugs(4, 3, HERE << conn << ", err=" << err);
    assert(Comm::IsConnOpen(conn));

    /* moved in front of errorBuildBuf @?@ */
    err->flags.flag_cbdata = 1;

    rep = err->BuildHttpReply();

    MemBuf *mb = rep->pack();
    AsyncCall::Pointer call = commCbCall(78, 5, "errorSendComplete",
                                         CommIoCbPtrFun(&errorSendComplete, err));
    Comm::Write(conn, mb, call);
    delete mb;

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
errorSendComplete(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    ErrorState *err = static_cast<ErrorState *>(data);
    debugs(4, 3, HERE << conn << ", size=" << size);

    if (errflag != COMM_ERR_CLOSING) {
        if (err->callback) {
            debugs(4, 3, "errorSendComplete: callback");
            err->callback(conn->fd, err->callback_data, size);
        } else {
            debugs(4, 3, "errorSendComplete: comm_close");
            conn->close();
        }
    }

    delete err;
}

ErrorState::~ErrorState()
{
    HTTPMSGUNLOCK(request);
    safe_free(redirect_url);
    safe_free(url);
    safe_free(request_hdrs);
    wordlistDestroy(&ftp.server_msg);
    safe_free(ftp.request);
    safe_free(ftp.reply);
#if USE_AUTH
    auth_user_request = NULL;
#endif
    safe_free(err_msg);
#if USE_ERR_LOCALES
    if (err_language != Config.errorDefaultLanguage)
#endif
        safe_free(err_language);
#if USE_SSL
    delete detail;
#endif
}

int
ErrorState::Dump(MemBuf * mb)
{
    MemBuf str;
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
#if USE_AUTH
    if (auth_user_request->denyMessage())
        str.Printf("Auth ErrMsg: %s\r\n", auth_user_request->denyMessage());
#endif
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

        str.Printf("%s " SQUIDSTRINGPH " %s/%d.%d\n",
                   RequestMethodStr(request->method),
                   SQUIDSTRINGPRINT(urlpath_or_slash),
                   AnyP::ProtocolType_str[request->http_ver.protocol],
                   request->http_ver.major, request->http_ver.minor);
        packerToMemInit(&pck, &str);
        request->header.packInto(&pck);
        packerClean(&pck);
    }

    str.Printf("\r\n");
    /* - FTP stuff */

    if (ftp.request) {
        str.Printf("FTP Request: %s\r\n", ftp.request);
        str.Printf("FTP Reply: %s\r\n", (ftp.reply? ftp.reply:"[none]"));
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
ErrorState::Convert(char token, bool building_deny_info_url, bool allowRecursion)
{
    static MemBuf mb;
    const char *p = NULL;	/* takes priority over mb if set */
    int do_quote = 1;
    int no_urlescape = 0;       /* if true then item is NOT to be further URL-encoded */
    char ntoabuf[MAX_IPSTRLEN];

    mb.reset();

    switch (token) {

    case 'a':
#if USE_AUTH
        if (request && request->auth_user_request != NULL)
            p = request->auth_user_request->username();
        if (!p)
#endif
            p = "-";
        break;

    case 'b':
        mb.Printf("%d", getMyPort());
        break;

    case 'B':
        if (building_deny_info_url) break;
        p = request ? ftpUrlWith2f(request) : "[no URL]";
        break;

    case 'c':
        if (building_deny_info_url) break;
        p = errorPageName(type);
        break;

    case 'D':
        if (!allowRecursion)
            p = "%D";  // if recursion is not allowed, do not convert
#if USE_SSL
        // currently only SSL error details implemented
        else if (detail) {
            detail->useRequest(request);
            const String &errDetail = detail->toString();
            if (errDetail.defined()) {
                MemBuf *detail_mb  = ConvertText(errDetail.termedBuf(), false);
                mb.append(detail_mb->content(), detail_mb->contentSize());
                delete detail_mb;
                do_quote = 0;
            }
        }
#endif
        if (!mb.contentSize())
            mb.Printf("[No Error Detail]");
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
        if (building_deny_info_url) break;
        /* FTP REQUEST LINE */
        if (ftp.request)
            p = ftp.request;
        else
            p = "nothing";
        break;

    case 'F':
        if (building_deny_info_url) break;
        /* FTP REPLY LINE */
        if (ftp.reply)
            p = ftp.reply;
        else
            p = "nothing";
        break;

    case 'g':
        if (building_deny_info_url) break;
        /* FTP SERVER RESPONSE */
        if (ftp.listing) {
            mb.append(ftp.listing->content(), ftp.listing->contentSize());
            do_quote = 0;
        } else if (ftp.server_msg) {
            wordlistCat(ftp.server_msg, &mb);
        }
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
        } else if (!building_deny_info_url)
            p = "[unknown host]";
        break;

    case 'i':
        mb.Printf("%s", src_addr.NtoA(ntoabuf,MAX_IPSTRLEN));
        break;

    case 'I':
        if (request && request->hier.tcpServer != NULL)
            p = request->hier.tcpServer->remote.NtoA(ntoabuf,MAX_IPSTRLEN);
        else if (!building_deny_info_url)
            p = "[unknown]";
        break;

    case 'l':
        if (building_deny_info_url) break;
        mb.append(error_stylesheet.content(), error_stylesheet.contentSize());
        do_quote = 0;
        break;

    case 'L':
        if (building_deny_info_url) break;
        if (Config.errHtmlText) {
            mb.Printf("%s", Config.errHtmlText);
            do_quote = 0;
        } else
            p = "[not available]";
        break;

    case 'm':
        if (building_deny_info_url) break;
#if USE_AUTH
        p = auth_user_request->denyMessage("[not available]");
#else
        p = "-";
#endif
        break;

    case 'M':
        if (request)
            p = RequestMethodStr(request->method);
        else if (!building_deny_info_url)
            p= "[unknown method]";
        break;

    case 'o':
        p = request ? request->extacl_message.termedBuf() : external_acl_message;
        if (!p && !building_deny_info_url)
            p = "[not available]";
        break;

    case 'p':
        if (request) {
            mb.Printf("%d", (int) request->port);
        } else if (!building_deny_info_url) {
            p = "[unknown port]";
        }
        break;

    case 'P':
        if (request) {
            p = AnyP::ProtocolType_str[request->protocol];
        } else if (!building_deny_info_url) {
            p = "[unknown protocol]";
        }
        break;

    case 'R':
        if (building_deny_info_url) {
            p = (request->urlpath.size() != 0 ? request->urlpath.termedBuf() : "/");
            no_urlescape = 1;
            break;
        }
        if (NULL != request) {
            Packer pck;
            String urlpath_or_slash;

            if (request->urlpath.size() != 0)
                urlpath_or_slash = request->urlpath;
            else
                urlpath_or_slash = "/";

            mb.Printf("%s " SQUIDSTRINGPH " %s/%d.%d\n",
                      RequestMethodStr(request->method),
                      SQUIDSTRINGPRINT(urlpath_or_slash),
                      AnyP::ProtocolType_str[request->http_ver.protocol],
                      request->http_ver.major, request->http_ver.minor);
            packerToMemInit(&pck, &mb);
            request->header.packInto(&pck, true); //hide authorization data
            packerClean(&pck);
        } else if (request_hdrs) {
            p = request_hdrs;
        } else {
            p = "[no request]";
        }
        break;

    case 's':
        /* for backward compat we make %s show the full URL. Drop this in some future release. */
        if (building_deny_info_url) {
            p = request ? urlCanonical(request) : url;
            debugs(0, DBG_CRITICAL, "WARNING: deny_info now accepts coded tags. Use %u to get the full URL instead of %s");
        } else
            p = visible_appname_string;
        break;

    case 'S':
        if (building_deny_info_url) {
            p = visible_appname_string;
            break;
        }
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
        mb.Printf("%s", Time::FormatHttpd(squid_curtime));
        break;

    case 'T':
        mb.Printf("%s", mkrfc1123(squid_curtime));
        break;

    case 'U':
        /* Using the fake-https version of canonical so error pages see https:// */
        /* even when the url-path cannot be shown as more than '*' */
        if (request)
            p = urlCanonicalFakeHttps(request);
        else if (url)
            p = url;
        else if (!building_deny_info_url)
            p = "[no URL]";
        break;

    case 'u':
        if (request)
            p = urlCanonical(request);
        else if (url)
            p = url;
        else if (!building_deny_info_url)
            p = "[no URL]";
        break;

    case 'w':
        if (Config.adminEmail)
            mb.Printf("%s", Config.adminEmail);
        else if (!building_deny_info_url)
            p = "[unknown]";
        break;

    case 'W':
        if (building_deny_info_url) break;
        if (Config.adminEmail && Config.onoff.emailErrData)
            Dump(&mb);
        no_urlescape = 1;
        break;

    case 'x':
#if USE_SSL
        if (detail)
            mb.Printf("%s", detail->errorName());
        else
#endif
            if (!building_deny_info_url)
                p = "[Unknown Error Code]";
        break;

    case 'z':
        if (building_deny_info_url) break;
        if (dnsError.size() > 0)
            p = dnsError.termedBuf();
        else if (ftp.cwd_msg)
            p = ftp.cwd_msg;
        else
            p = "[unknown]";
        break;

    case 'Z':
        if (building_deny_info_url) break;
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

    if (building_deny_info_url && !no_urlescape)
        p = rfc1738_escape_part(p);

    return p;
}

void
ErrorState::DenyInfoLocation(const char *name, HttpRequest *aRequest, MemBuf &result)
{
    char const *m = name;
    char const *p = m;
    char const *t;

    if (m[0] == '3')
        m += 4; // skip "3xx:"

    while ((p = strchr(m, '%'))) {
        result.append(m, p - m);       /* copy */
        t = Convert(*++p, true, true);       /* convert */
        result.Printf("%s", t);        /* copy */
        m = p + 1;                     /* advance */
    }

    if (*m)
        result.Printf("%s", m);        /* copy tail */

    assert((size_t)result.contentSize() == strlen(result.content()));
}

HttpReply *
ErrorState::BuildHttpReply()
{
    HttpReply *rep = new HttpReply;
    const char *name = errorPageName(page_id);
    /* no LMT for error pages; error pages expire immediately */

    if (name[0] == '3' || (name[0] != '2' && name[0] != '4' && name[0] != '5' && strchr(name, ':'))) {
        /* Redirection */
        http_status status = HTTP_MOVED_TEMPORARILY;
        // Use configured 3xx reply status if set.
        if (name[0] == '3')
            status = httpStatus;
        else {
            // Use 307 for HTTP/1.1 non-GET/HEAD requests.
            if (request->method != METHOD_GET && request->method != METHOD_HEAD && request->http_ver >= HttpVersion(1,1))
                status = HTTP_TEMPORARY_REDIRECT;
        }

        rep->setHeaders(status, NULL, "text/html", 0, 0, -1);

        if (request) {
            MemBuf redirect_location;
            redirect_location.init();
            DenyInfoLocation(name, request, redirect_location);
            httpHeaderPutStrf(&rep->header, HDR_LOCATION, "%s", redirect_location.content() );
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

        rep->body.setMb(content);
        /* do not memBufClean() or delete the content, it was absorbed by httpBody */
    }

    // Make sure error codes get back to the client side for logging and
    // error tracking.
    if (request) {
        int edc = ERR_DETAIL_NONE; // error detail code
#if USE_SSL
        if (detail)
            edc = detail->errorNo();
        else
#endif
            if (detailCode)
                edc = detailCode;
            else
                edc = xerrno;
        request->detailError(type, edc);
    }

    return rep;
}

MemBuf *
ErrorState::BuildContent()
{
    const char *m = NULL;

    assert(page_id > ERR_NONE && page_id < error_page_count);

#if USE_ERR_LOCALES
    ErrorPageFile *localeTmpl = NULL;

    /** error_directory option in squid.conf overrides translations.
     * Custom errors are always found either in error_directory or the templates directory.
     * Otherwise locate the Accept-Language header
     */
    if (!Config.errorDirectory && page_id < ERR_MAX) {
        if (err_language && err_language != Config.errorDefaultLanguage)
            safe_free(err_language);

        localeTmpl = new ErrorPageFile(err_type_str[page_id], static_cast<err_type>(page_id));
        if (localeTmpl->loadFor(request)) {
            m = localeTmpl->text();
            assert(localeTmpl->language());
            err_language = xstrdup(localeTmpl->language());
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

    MemBuf *result = ConvertText(m, true);
#if USE_ERR_LOCALES
    if (localeTmpl)
        delete localeTmpl;
#endif
    return result;
}

MemBuf *ErrorState::ConvertText(const char *text, bool allowRecursion)
{
    MemBuf *content = new MemBuf;
    const char *p;
    const char *m = text;
    assert(m);
    content->init();

    while ((p = strchr(m, '%'))) {
        content->append(m, p - m);	/* copy */
        const char *t = Convert(*++p, false, allowRecursion);	/* convert */
        content->Printf("%s", t);	/* copy */
        m = p + 1;			/* advance */
    }

    if (*m)
        content->Printf("%s", m);	/* copy tail */

    assert((size_t)content->contentSize() == strlen(content->content()));

    return content;
}
