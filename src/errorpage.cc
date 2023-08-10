/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 04    Error Generation */

#include "squid.h"
#include "AccessLogEntry.h"
#include "cache_cf.h"
#include "clients/forward.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "error/Detail.h"
#include "error/SysErrorDetail.h"
#include "errorpage.h"
#include "fde.h"
#include "format/Format.h"
#include "fs_io.h"
#include "html_quote.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "rfc1738.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "Store.h"
#include "tools.h"
#include "wordlist.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_OPENSSL
#include "ssl/ErrorDetailManager.h"
#endif

#include <array>

/**
 \defgroup ErrorPageInternal Error Page Internals
 \ingroup ErrorPageAPI
 *
 \section ErrorPagesAbstract Abstract:
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

const SBuf ErrorState::LogformatMagic("@Squid{");

/* local types */

/// an error page created from admin-configurable metadata (e.g. deny_info)
class ErrorDynamicPageInfo {
public:
    ErrorDynamicPageInfo(const int anId, const char *aName, const SBuf &aCfgLocation);
    ~ErrorDynamicPageInfo() { xfree(page_name); }

    /// error_text[] index for response body (unused in redirection responses)
    int id;

    /// Primary deny_info parameter:
    /// * May start with an HTTP status code.
    /// * Either a well-known error page name, a filename, or a redirect URL.
    char *page_name;

    /// admin-configured HTTP Location header value for redirection responses
    const char *uri;

    /// admin-configured name for the error page template (custom or standard)
    const char *filename;

    /// deny_info directive position in squid.conf (for reporting)
    SBuf cfgLocation;

    // XXX: Misnamed. Not just for redirects.
    /// admin-configured HTTP status code
    Http::StatusCode page_redirect;

private:
    // no copying of any kind
    ErrorDynamicPageInfo(ErrorDynamicPageInfo &&) = delete;
};

namespace ErrorPage {

/// state and parameters shared by several ErrorState::compile*() methods
class Build
{
public:
    SBuf output; ///< compilation result
    const char *input = nullptr; ///< template bytes that need to be compiled
    bool building_deny_info_url = false; ///< whether we compile deny_info URI
    bool allowRecursion = false; ///< whether top-level compile() calls are OK
};

/// pretty-prints error page/deny_info building error
class BuildErrorPrinter
{
public:
    BuildErrorPrinter(const SBuf &anInputLocation, int aPage, const char *aMsg, const char *aNear): inputLocation(anInputLocation), page_id(aPage), msg(aMsg), near(aNear) {}

    /// reports error details (for admin-visible exceptions and debugging)
    std::ostream &print(std::ostream &) const;

    /// print() helper to report where the error was found
    std::ostream &printLocation(std::ostream &os) const;

    /* saved constructor parameters */
    const SBuf &inputLocation;
    const int page_id;
    const char *msg;
    const char *near;
};

static inline std::ostream &
operator <<(std::ostream &os, const BuildErrorPrinter &context)
{
    return context.print(os);
}

static const char *IsDenyInfoUri(const int page_id);

static void ImportStaticErrorText(const int page_id, const char *text, const SBuf &inputLocation);
static void ValidateStaticError(const int page_id, const SBuf &inputLocation);

} // namespace ErrorPage

/* local constant and vars */

/// an error page (or a part of an error page) with hard-coded template text
class HardCodedError {
public:
    err_type type; ///< identifies the error (or a special error template part)
    const char *text; ///< a string literal containing the error template
};

/// error messages that cannot be configured/customized externally
static const std::array<HardCodedError, 7> HardCodedErrors = {
    {
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
        },
        {
            ERR_CLIENT_GONE,
            "unexpected client disconnect"
        },
        {
            ERR_SECURE_ACCEPT_FAIL,
            "secure accept fail"
        },
        {
            ERR_REQUEST_START_TIMEOUT,
            "request start timedout"
        },
        {
            ERR_REQUEST_PARSE_TIMEOUT,
            "request parse timedout"
        },
        {
            ERR_RELAY_REMOTE,
            "relay server response"
        }
    }
};

/// \ingroup ErrorPageInternal
static std::vector<ErrorDynamicPageInfo *> ErrorDynamicPages;

/* local prototypes */

/// \ingroup ErrorPageInternal
static char **error_text = nullptr;

/// \ingroup ErrorPageInternal
static int error_page_count = 0;

/// \ingroup ErrorPageInternal
static MemBuf error_stylesheet;

static const char *errorFindHardText(err_type type);
static IOCB errorSendComplete;

/// \ingroup ErrorPageInternal
/// manages an error page template
class ErrorPageFile: public TemplateFile
{
public:
    ErrorPageFile(const char *name, const err_type code) : TemplateFile(name, code) {}

    /// The template text data read from disk
    const char *text() { return template_.c_str(); }

protected:
    void setDefault() override {
        template_ = "Internal Error: Missing Template ";
        template_.append(templateName.termedBuf());
    }
};

/// \ingroup ErrorPageInternal
static err_type &
operator++ (err_type &anErr)
{
    int tmp = (int)anErr;
    anErr = (err_type)(++tmp);
    return anErr;
}

/// \ingroup ErrorPageInternal
static int
operator -(err_type const &anErr, err_type const &anErr2)
{
    return (int)anErr - (int)anErr2;
}

/// \return deny_info URL if the given page is a deny_info page with a URL
/// \return nullptr otherwise
static const char *
ErrorPage::IsDenyInfoUri(const int page_id)
{
    if (ERR_MAX <= page_id && page_id < error_page_count)
        return ErrorDynamicPages.at(page_id - ERR_MAX)->uri; // may be nil
    return nullptr;
}

void
errorInitialize(void)
{
    using ErrorPage::ImportStaticErrorText;

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
            static const SBuf builtIn("built-in");
            ImportStaticErrorText(i, text, builtIn);

        } else if (i < ERR_MAX) {
            /**\par
             * Index precompiled fixed template files from one of two sources:
             *  (a) default language translation directory (error_default_language)
             *  (b) admin specified custom directory (error_directory)
             */
            ErrorPageFile errTmpl(err_type_str[i], i);
            errTmpl.loadDefault();
            ImportStaticErrorText(i, errTmpl.text(), errTmpl.filename);
        } else {
            /** \par
             * Index any unknown file names used by deny_info.
             */
            ErrorDynamicPageInfo *info = ErrorDynamicPages.at(i - ERR_MAX);
            assert(info && info->id == i && info->page_name);

            if (info->filename) {
                /** But only if they are not redirection URL. */
                ErrorPageFile errTmpl(info->filename, ERR_MAX);
                errTmpl.loadDefault();
                ImportStaticErrorText(i, errTmpl.text(), errTmpl.filename);
            } else {
                assert(info->uri);
                ErrorPage::ValidateStaticError(i, info->cfgLocation);
            }
        }
    }

    error_stylesheet.reset();

    // look for and load stylesheet into global MemBuf for it.
    if (Config.errorStylesheet) {
        ErrorPageFile tmpl("StylesSheet", ERR_MAX);
        tmpl.loadFromFile(Config.errorStylesheet);
        error_stylesheet.appendf("%s",tmpl.text());
    }

#if USE_OPENSSL
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

    while (!ErrorDynamicPages.empty()) {
        delete ErrorDynamicPages.back();
        ErrorDynamicPages.pop_back();
    }

    error_page_count = 0;

#if USE_OPENSSL
    Ssl::errorDetailClean();
#endif
}

/// \ingroup ErrorPageInternal
static const char *
errorFindHardText(err_type type)
{
    for (const auto &m: HardCodedErrors) {
        if (m.type == type)
            return m.text;
    }
    return nullptr;
}

TemplateFile::TemplateFile(const char *name, const err_type code): silent(false), wasLoaded(false), templateName(name), templateCode(code)
{
    assert(name);
}

void
TemplateFile::loadDefault()
{
    if (loaded()) // already loaded?
        return;

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
            debugs(1, (templateCode < TCP_RESET ? DBG_CRITICAL : 3), "ERROR: Unable to load default error language files. Reset to backups.");
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
        template_.clear();
        setDefault();
        wasLoaded = true;
    }
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
        debugs(4,2, "wildcard fallback errors not coded yet.");
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
        if (!silent && templateCode < TCP_RESET) {
            int xerrno = errno;
            debugs(4, DBG_CRITICAL, "ERROR: loading file '" << path << "': " << xstrerr(xerrno));
        }
        wasLoaded = false;
        return wasLoaded;
    }

    template_.clear();
    while ((len = FD_READ_METHOD(fd, buf, sizeof(buf))) > 0) {
        template_.append(buf, len);
    }

    if (len < 0) {
        int xerrno = errno;
        file_close(fd);
        debugs(4, DBG_CRITICAL, MYNAME << "ERROR: failed to fully read: '" << path << "': " << xstrerr(xerrno));
        wasLoaded = false;
        return false;
    }

    file_close(fd);

    filename = SBuf(path);

    if (!parse()) {
        debugs(4, DBG_CRITICAL, "ERROR: parsing error in template file: " << path);
        wasLoaded = false;
        return false;
    }

    wasLoaded = true;
    return wasLoaded;
}

bool strHdrAcptLangGetItem(const String &hdr, char *lang, int langLen, size_t &pos)
{
    while (pos < hdr.size()) {

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
        char *dt = lang;
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

        // if we terminated the tag on garbage or ';' we need to skip to the next ',' or end of header.
        while (pos < hdr.size() && hdr[pos] != ',')
            ++pos;

        if (pos < hdr.size() && hdr[pos] == ',')
            ++pos;

        debugs(4, 9, "STATE: lang=" << lang << ", pos=" << pos << ", buf='" << ((pos < hdr.size()) ? hdr.substr(pos,hdr.size()) : "") << "'");

        /* if we found anything we might use, try it. */
        if (*lang != '\0' && !invalid_byte)
            return true;
    }
    return false;
}

bool
TemplateFile::loadFor(const HttpRequest *request)
{
    String hdr;

#if USE_ERR_LOCALES
    if (loaded()) // already loaded?
        return true;

    if (!request || !request->header.getList(Http::HdrType::ACCEPT_LANGUAGE, &hdr))
        return false;

    char lang[256];
    size_t pos = 0; // current parsing position in header string

    debugs(4, 6, "Testing Header: '" << hdr << "'");

    while ( strHdrAcptLangGetItem(hdr, lang, 256, pos) ) {

        /* wildcard uses the configured default language */
        if (lang[0] == '*' && lang[1] == '\0') {
            debugs(4, 6, "Found language '" << lang << "'. Using configured default.");
            return false;
        }

        debugs(4, 6, "Found language '" << lang << "', testing for available template");

        if (tryLoadTemplate(lang)) {
            /* store the language we found for the Content-Language reply header */
            errLanguage = lang;
            break;
        } else if (Config.errorLogMissingLanguages) {
            debugs(4, DBG_IMPORTANT, "WARNING: Error Pages Missing Language: " << lang);
        }
    }
#else
    (void)request;
#endif

    return loaded();
}

ErrorDynamicPageInfo::ErrorDynamicPageInfo(const int anId, const char *aName, const SBuf &aCfgLocation):
    id(anId),
    page_name(xstrdup(aName)),
    uri(nullptr),
    filename(nullptr),
    cfgLocation(aCfgLocation),
    page_redirect(static_cast<Http::StatusCode>(atoi(page_name)))
{
    const char *filenameOrUri = nullptr;
    if (xisdigit(*page_name)) {
        if (const char *statusCodeEnd = strchr(page_name, ':'))
            filenameOrUri = statusCodeEnd + 1;
    } else {
        assert(!page_redirect);
        filenameOrUri = page_name;
    }

    // Guessed uri, filename, or both values may be nil or malformed.
    // They are validated later.
    if (!page_redirect) {
        if (filenameOrUri && strchr(filenameOrUri, ':')) // looks like a URL
            uri = filenameOrUri;
        else
            filename = filenameOrUri;
    }
    else if (page_redirect/100 == 3) {
        // redirects imply a URL
        uri = filenameOrUri;
    } else {
        // non-redirects imply an error page name
        filename = filenameOrUri;
    }

    const auto info = this; // source code change reduction hack
    // TODO: Move and refactor to avoid self_destruct()s in reconfigure.

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
    if (info->page_redirect == Http::scNone)
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
        if (strcmp(ErrorDynamicPages[j]->page_name, page_name) == 0)
            return j + ERR_MAX;
    }

    return ERR_NONE;
}

err_type
errorReservePageId(const char *page_name, const SBuf &cfgLocation)
{
    int id = errorPageId(page_name);

    if (id == ERR_NONE) {
        id = ERR_MAX + ErrorDynamicPages.size();
        const auto info = new ErrorDynamicPageInfo(id, page_name, cfgLocation);
        ErrorDynamicPages.push_back(info);
    }

    return (err_type)id;
}

/// \ingroup ErrorPageInternal
const char *
errorPageName(int pageId)
{
    if (pageId >= ERR_NONE && pageId < ERR_MAX)     /* common case */
        return err_type_str[pageId];

    if (pageId >= ERR_MAX && pageId - ERR_MAX < (ssize_t)ErrorDynamicPages.size())
        return ErrorDynamicPages[pageId - ERR_MAX]->page_name;

    return "ERR_UNKNOWN";   /* should not happen */
}

ErrorState *
ErrorState::NewForwarding(err_type type, HttpRequestPointer &request, const AccessLogEntry::Pointer &ale)
{
    const Http::StatusCode status = (request && request->flags.needValidation) ?
                                    Http::scGatewayTimeout : Http::scServiceUnavailable;
    return new ErrorState(type, status, request.getRaw(), ale);
}

ErrorState::ErrorState(err_type t) :
    type(t),
    page_id(t),
    callback(nullptr)
{
}

ErrorState::ErrorState(err_type t, Http::StatusCode status, HttpRequest * req, const AccessLogEntry::Pointer &anAle) :
    ErrorState(t)
{
    if (page_id >= ERR_MAX && ErrorDynamicPages[page_id - ERR_MAX]->page_redirect != Http::scNone)
        httpStatus = ErrorDynamicPages[page_id - ERR_MAX]->page_redirect;
    else
        httpStatus = status;

    if (req) {
        request = req;
        src_addr = req->client_addr;
    }

    ale = anAle;
}

ErrorState::ErrorState(HttpRequest * req, HttpReply *errorReply) :
    ErrorState(ERR_RELAY_REMOTE)
{
    Must(errorReply);
    response_ = errorReply;
    httpStatus = errorReply->sline.status();

    if (req) {
        request = req;
        src_addr = req->client_addr;
    }
}

void
errorAppendEntry(StoreEntry * entry, ErrorState * err)
{
    assert(entry->mem_obj != nullptr);
    assert (entry->isEmpty());
    debugs(4, 4, "storing " << err << " in " << *entry);

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
            err->request->flags.resetTcp = true;
        }
    }

    entry->storeErrorResponse(err->BuildHttpReply());
    delete err;
}

void
errorSend(const Comm::ConnectionPointer &conn, ErrorState * err)
{
    debugs(4, 3, conn << ", err=" << err);
    assert(Comm::IsConnOpen(conn));

    HttpReplyPointer rep(err->BuildHttpReply());

    MemBuf *mb = rep->pack();
    AsyncCall::Pointer call = commCbCall(78, 5, "errorSendComplete",
                                         CommIoCbPtrFun(&errorSendComplete, err));
    Comm::Write(conn, mb, call);
    delete mb;
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
errorSendComplete(const Comm::ConnectionPointer &conn, char *, size_t size, Comm::Flag errflag, int, void *data)
{
    ErrorState *err = static_cast<ErrorState *>(data);
    debugs(4, 3, conn << ", size=" << size);

    if (errflag != Comm::ERR_CLOSING) {
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
    safe_free(redirect_url);
    safe_free(url);
    safe_free(request_hdrs);
    wordlistDestroy(&ftp.server_msg);
    safe_free(ftp.request);
    safe_free(ftp.reply);
    safe_free(err_msg);
#if USE_ERR_LOCALES
    if (err_language != Config.errorDefaultLanguage)
#endif
        safe_free(err_language);
}

int
ErrorState::Dump(MemBuf * mb)
{
    MemBuf str;
    char ntoabuf[MAX_IPSTRLEN];

    str.reset();
    /* email subject line */
    str.appendf("CacheErrorInfo - %s", errorPageName(type));
    mb->appendf("?subject=%s", rfc1738_escape_part(str.buf));
    str.reset();
    /* email body */
    str.appendf("CacheHost: %s\r\n", getMyHostname());
    /* - Err Msgs */
    str.appendf("ErrPage: %s\r\n", errorPageName(type));

    if (xerrno) {
        str.appendf("Err: (%d) %s\r\n", xerrno, strerror(xerrno));
    } else {
        str.append("Err: [none]\r\n", 13);
    }
#if USE_AUTH
    if (auth_user_request.getRaw() && auth_user_request->denyMessage())
        str.appendf("Auth ErrMsg: %s\r\n", auth_user_request->denyMessage());
#endif
    if (dnsError)
        str.appendf("DNS ErrMsg: " SQUIDSBUFPH "\r\n", SQUIDSBUFPRINT(*dnsError));

    /* - TimeStamp */
    str.appendf("TimeStamp: %s\r\n\r\n", Time::FormatRfc1123(squid_curtime));

    /* - IP stuff */
    str.appendf("ClientIP: %s\r\n", src_addr.toStr(ntoabuf,MAX_IPSTRLEN));

    if (request && request->hier.host[0] != '\0') {
        str.appendf("ServerIP: %s\r\n", request->hier.host);
    }

    str.append("\r\n", 2);
    /* - HTTP stuff */
    str.append("HTTP Request:\r\n", 15);
    if (request) {
        str.appendf(SQUIDSBUFPH " " SQUIDSBUFPH " %s/%d.%d\n",
                    SQUIDSBUFPRINT(request->method.image()),
                    SQUIDSBUFPRINT(request->url.path()),
                    AnyP::ProtocolType_str[request->http_ver.protocol],
                    request->http_ver.major, request->http_ver.minor);
        request->header.packInto(&str);
    }

    str.append("\r\n", 2);
    /* - FTP stuff */

    if (ftp.request) {
        str.appendf("FTP Request: %s\r\n", ftp.request);
        str.appendf("FTP Reply: %s\r\n", (ftp.reply? ftp.reply:"[none]"));
        str.append("FTP Msg: ", 9);
        wordlistCat(ftp.server_msg, &str);
        str.append("\r\n", 2);
    }

    str.append("\r\n", 2);
    mb->appendf("&body=%s", rfc1738_escape_part(str.buf));
    str.clean();
    return 0;
}

/// \ingroup ErrorPageInternal
#define CVT_BUF_SZ 512

void
ErrorState::compileLogformatCode(Build &build)
{
    assert(LogformatMagic.cmp(build.input, LogformatMagic.length()) == 0);

    try {
        const auto logformat = build.input + LogformatMagic.length();

        // Logformat supports undocumented "external" encoding specifications
        // like [%>h] or "%<a". To preserve the possibility of extending
        // @Squid{} syntax to non-logformat sequences, we require logformat
        // sequences to start with '%'. This restriction does not limit
        // logformat quoting abilities. TODO: Deprecate "external" encoding?
        if (*logformat != '%')
            throw TexcHere("logformat expressions that do not start with % are not supported");

        static MemBuf result;
        result.reset();
        const auto logformatLen = Format::AssembleOne(logformat, result, ale);
        assert(logformatLen > 0);
        const auto closure = logformat + logformatLen;
        if (*closure != '}')
            throw TexcHere("Missing closing brace (})");
        build.output.append(result.content(), result.contentSize());
        build.input = closure + 1;
        return;
    } catch (...) {
        noteBuildError("Bad @Squid{logformat} sequence", build.input);
    }

    // we cannot recover reliably so stop interpreting the rest of input
    const auto remainingSize = strlen(build.input);
    build.output.append(build.input, remainingSize);
    build.input += remainingSize;
}

void
ErrorState::compileLegacyCode(Build &build)
{
    static MemBuf mb;
    const char *p = nullptr;   /* takes priority over mb if set */
    int do_quote = 1;
    int no_urlescape = 0;       /* if true then item is NOT to be further URL-encoded */
    char ntoabuf[MAX_IPSTRLEN];

    mb.reset();

    const auto &building_deny_info_url = build.building_deny_info_url; // a change reduction hack

    const auto letter = build.input[1];

    switch (letter) {

    case 'a':
#if USE_AUTH
        if (request && request->auth_user_request)
            p = request->auth_user_request->username();
        if (!p)
#endif
            p = "-";
        break;

    case 'A':
        // TODO: When/if we get ALE here, pass it as well
        if (const auto addr = FindListeningPortAddress(request.getRaw(), nullptr))
            mb.appendf("%s", addr->toStr(ntoabuf, MAX_IPSTRLEN));
        else
            p = "-";
        break;

    case 'b':
        mb.appendf("%u", getMyPort());
        break;

    case 'B':
        if (building_deny_info_url) break;
        if (request) {
            const SBuf &tmp = Ftp::UrlWith2f(request.getRaw());
            mb.append(tmp.rawContent(), tmp.length());
        } else
            p = "[no URL]";
        break;

    case 'c':
        if (building_deny_info_url) break;
        p = errorPageName(type);
        break;

    case 'D':
        if (!build.allowRecursion)
            p = "%D";  // if recursion is not allowed, do not convert
        else if (detail) {
            auto rawDetail = detail->verbose(request);
            // XXX: Performance regression. c_str() reallocates
            const auto compiledDetail = compileBody(rawDetail.c_str(), false);
            mb.append(compiledDetail.rawContent(), compiledDetail.length());
            do_quote = 0;
        }
        if (!mb.contentSize())
            mb.append("[No Error Detail]", 17);
        break;

    case 'e':
        mb.appendf("%d", xerrno);
        break;

    case 'E':
        if (xerrno)
            mb.appendf("(%d) %s", xerrno, strerror(xerrno));
        else
            mb.append("[No Error]", 10);
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
        mb.appendf("%s", getMyHostname());
        break;

    case 'H':
        if (request) {
            if (request->hier.host[0] != '\0') // if non-empty string.
                p = request->hier.host;
            else
                p = request->url.host();
        } else if (!building_deny_info_url)
            p = "[unknown host]";
        break;

    case 'i':
        mb.appendf("%s", src_addr.toStr(ntoabuf,MAX_IPSTRLEN));
        break;

    case 'I':
        if (request && request->hier.tcpServer)
            p = request->hier.tcpServer->remote.toStr(ntoabuf,MAX_IPSTRLEN);
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
            mb.appendf("%s", Config.errHtmlText);
            do_quote = 0;
        } else
            p = "[not available]";
        break;

    case 'm':
        if (building_deny_info_url) break;
#if USE_AUTH
        if (auth_user_request.getRaw())
            p = auth_user_request->denyMessage("[not available]");
        else
            p = "[not available]";
#else
        p = "-";
#endif
        break;

    case 'M':
        if (request) {
            const SBuf &m = request->method.image();
            mb.append(m.rawContent(), m.length());
        } else if (!building_deny_info_url)
            p = "[unknown method]";
        break;

    case 'O':
        if (!building_deny_info_url)
            do_quote = 0;
        [[fallthrough]];
    case 'o':
        p = request ? request->extacl_message.termedBuf() : external_acl_message;
        if (!p && !building_deny_info_url)
            p = "[not available]";
        break;

    case 'p':
        if (request) {
            mb.appendf("%u", request->url.port());
        } else if (!building_deny_info_url) {
            p = "[unknown port]";
        }
        break;

    case 'P':
        if (request) {
            const SBuf &m = request->url.getScheme().image();
            mb.append(m.rawContent(), m.length());
        } else if (!building_deny_info_url) {
            p = "[unknown protocol]";
        }
        break;

    case 'R':
        if (building_deny_info_url) {
            if (request != nullptr) {
                const SBuf &tmp = request->url.path();
                mb.append(tmp.rawContent(), tmp.length());
                no_urlescape = 1;
            } else
                p = "[no request]";
            break;
        }
        if (request) {
            mb.appendf(SQUIDSBUFPH " " SQUIDSBUFPH " %s/%d.%d\n",
                       SQUIDSBUFPRINT(request->method.image()),
                       SQUIDSBUFPRINT(request->url.path()),
                       AnyP::ProtocolType_str[request->http_ver.protocol],
                       request->http_ver.major, request->http_ver.minor);
            request->header.packInto(&mb, true); //hide authorization data
        } else if (request_hdrs) {
            p = request_hdrs;
        } else {
            p = "[no request]";
        }
        break;

    case 's':
        /* for backward compat we make %s show the full URL. Drop this in some future release. */
        if (building_deny_info_url) {
            if (request) {
                const SBuf &tmp = request->effectiveRequestUri();
                mb.append(tmp.rawContent(), tmp.length());
            } else
                p = url;
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
            const auto signature = buildBody();
            mb.append(signature.rawContent(), signature.length());
            page_id = saved_id;
            do_quote = 0;
        } else {
            /* wow, somebody put %S into ERR_SIGNATURE, stop recursion */
            p = "[%S]";
        }
        break;

    case 't':
        mb.appendf("%s", Time::FormatHttpd(squid_curtime));
        break;

    case 'T':
        mb.appendf("%s", Time::FormatRfc1123(squid_curtime));
        break;

    case 'U':
        /* Using the fake-https version of absolute-URI so error pages see https:// */
        /* even when the url-path cannot be shown as more than '*' */
        if (request)
            p = urlCanonicalFakeHttps(request.getRaw());
        else if (url)
            p = url;
        else if (!building_deny_info_url)
            p = "[no URL]";
        break;

    case 'u':
        if (request) {
            const SBuf &tmp = request->effectiveRequestUri();
            mb.append(tmp.rawContent(), tmp.length());
        } else if (url)
            p = url;
        else if (!building_deny_info_url)
            p = "[no URL]";
        break;

    case 'w':
        if (Config.adminEmail)
            mb.appendf("%s", Config.adminEmail);
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
        if (detail) {
            const auto brief = detail->brief();
            mb.append(brief.rawContent(), brief.length());
        } else if (!building_deny_info_url) {
            p = "[Unknown Error Code]";
        }
        break;

    case 'z':
        if (building_deny_info_url) break;
        if (dnsError)
            p = dnsError->c_str();
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
        if (building_deny_info_url)
            bypassBuildErrorXXX("Unsupported deny_info %code", build.input);
        else if (letter != ';')
            bypassBuildErrorXXX("Unsupported error page %code", build.input);
        // else too many "font-size: 100%;" template errors to report

        mb.append(build.input, 2);
        do_quote = 0;
        break;
    }

    if (!p)
        p = mb.buf;     /* do not use mb after this assignment! */

    assert(p);

    debugs(4, 3, "%" << letter << " --> '" << p << "'" );

    if (do_quote)
        p = html_quote(p);

    if (building_deny_info_url && !no_urlescape)
        p = rfc1738_escape_part(p);

    // TODO: Optimize by replacing mb with direct build.output usage.
    build.output.append(p, strlen(p));
    build.input += 2;
}

void
ErrorState::validate()
{
    if (const auto urlTemplate = ErrorPage::IsDenyInfoUri(page_id)) {
        (void)compile(urlTemplate, true, true);
    } else {
        assert(page_id > ERR_NONE);
        assert(page_id < error_page_count);
        (void)compileBody(error_text[page_id], true);
    }
}

HttpReply *
ErrorState::BuildHttpReply()
{
    if (response_)
        return response_.getRaw();

    HttpReply *rep = new HttpReply;
    const char *name = errorPageName(page_id);
    /* no LMT for error pages; error pages expire immediately */

    if (const auto urlTemplate = ErrorPage::IsDenyInfoUri(page_id)) {
        /* Redirection */
        Http::StatusCode status = Http::scFound;
        // Use configured 3xx reply status if set.
        if (name[0] == '3')
            status = httpStatus;
        else {
            // Use 307 for HTTP/1.1 non-GET/HEAD requests.
            if (request && request->method != Http::METHOD_GET && request->method != Http::METHOD_HEAD && request->http_ver >= Http::ProtocolVersion(1,1))
                status = Http::scTemporaryRedirect;
        }

        rep->setHeaders(status, nullptr, "text/html;charset=utf-8", 0, 0, -1);

        if (request) {
            auto location = compile(urlTemplate, true, true);
            rep->header.putStr(Http::HdrType::LOCATION, location.c_str());
        }

        httpHeaderPutStrf(&rep->header, Http::HdrType::X_SQUID_ERROR, "%d %s", httpStatus, "Access Denied");
    } else {
        const auto body = buildBody();
        rep->setHeaders(httpStatus, nullptr, "text/html;charset=utf-8", body.length(), 0, -1);
        /*
         * include some information for downstream caches. Implicit
         * replaceable content. This isn't quite sufficient. xerrno is not
         * necessarily meaningful to another system, so we really should
         * expand it. Additionally, we should identify ourselves. Someone
         * might want to know. Someone _will_ want to know OTOH, the first
         * X-CACHE-MISS entry should tell us who.
         */
        httpHeaderPutStrf(&rep->header, Http::HdrType::X_SQUID_ERROR, "%s %d", name, xerrno);

#if USE_ERR_LOCALES
        /*
         * If error page auto-negotiate is enabled in any way, send the Vary.
         * RFC 2616 section 13.6 and 14.44 says MAY and SHOULD do this.
         * We have even better reasons though:
         * see https://wiki.squid-cache.org/KnowledgeBase/VaryNotCaching
         */
        if (!Config.errorDirectory) {
            /* We 'negotiated' this ONLY from the Accept-Language. */
            static const SBuf acceptLanguage("Accept-Language");
            rep->header.updateOrAddStr(Http::HdrType::VARY, acceptLanguage);
        }

        /* add the Content-Language header according to RFC section 14.12 */
        if (err_language) {
            rep->header.putStr(Http::HdrType::CONTENT_LANGUAGE, err_language);
        } else
#endif /* USE_ERROR_LOCALES */
        {
            /* default templates are in English */
            /* language is known unless error_directory override used */
            if (!Config.errorDirectory)
                rep->header.putStr(Http::HdrType::CONTENT_LANGUAGE, "en");
        }

        rep->body.set(body);
    }

    // Make sure error codes get back to the client side for logging and
    // error tracking.
    if (request) {
        if (detail)
            request->detailError(type, detail);
        else
            request->detailError(type, SysErrorDetail::NewIfAny(xerrno));
    } else if (ale) {
        if (detail)
            ale->updateError(Error(type, detail));
        else
            ale->updateError(Error(type, SysErrorDetail::NewIfAny(xerrno)));
    }

    return rep;
}

SBuf
ErrorState::buildBody()
{
    assert(page_id > ERR_NONE && page_id < error_page_count);

#if USE_ERR_LOCALES
    /** error_directory option in squid.conf overrides translations.
     * Custom errors are always found either in error_directory or the templates directory.
     * Otherwise locate the Accept-Language header
     */
    if (!Config.errorDirectory && page_id < ERR_MAX) {
        if (err_language && err_language != Config.errorDefaultLanguage)
            safe_free(err_language);

        ErrorPageFile localeTmpl(err_type_str[page_id], static_cast<err_type>(page_id));
        if (localeTmpl.loadFor(request.getRaw())) {
            inputLocation = localeTmpl.filename;
            assert(localeTmpl.language());
            err_language = xstrdup(localeTmpl.language());
            return compileBody(localeTmpl.text(), true);
        }
    }
#endif /* USE_ERR_LOCALES */

    /** \par
     * If client-specific error templates are not enabled or available.
     * fall back to the old style squid.conf settings.
     */
#if USE_ERR_LOCALES
    if (!Config.errorDirectory)
        err_language = Config.errorDefaultLanguage;
#endif
    debugs(4, 2, "No existing error page language negotiated for " << this << ". Using default error file.");
    return compileBody(error_text[page_id], true);
}

SBuf
ErrorState::compileBody(const char *input, bool allowRecursion)
{
    return compile(input, false, allowRecursion);
}

SBuf
ErrorState::compile(const char *input, bool building_deny_info_url, bool allowRecursion)
{
    assert(input);

    Build build;
    build.building_deny_info_url = building_deny_info_url;
    build.allowRecursion = allowRecursion;
    build.input = input;

    auto blockStart = build.input;
    while (const auto letter = *build.input) {
        if (letter == '%') {
            build.output.append(blockStart, build.input - blockStart);
            compileLegacyCode(build);
            blockStart = build.input;
        }
        else if (letter == '@' && LogformatMagic.cmp(build.input, LogformatMagic.length()) == 0) {
            build.output.append(blockStart, build.input - blockStart);
            compileLogformatCode(build);
            blockStart = build.input;
        } else {
            ++build.input;
        }
    }
    build.output.append(blockStart, build.input - blockStart);
    return build.output;
}

/// react to a compile() error
/// \param msg  description of what went wrong
/// \param near  approximate start of the problematic input
/// \param  forceBypass whether detection of this error was introduced late,
/// after old configurations containing this error could have been
/// successfully validated and deployed (i.e. the admin may not be
/// able to fix this newly detected but old problem quickly)
void
ErrorState::noteBuildError_(const char *msg, const char *near, const bool forceBypass)
{
    using ErrorPage::BuildErrorPrinter;
    const auto runtime = !starting_up;
    if (runtime || forceBypass) {
        // swallow this problem because the admin may not be (and/or the page
        // building code is not) ready to handle throwing consequences

        static unsigned int seenErrors = 0;
        ++seenErrors;

        const auto debugLevel =
            (seenErrors > 100) ? DBG_DATA:
            (starting_up || reconfiguring) ? DBG_CRITICAL:
            3; // most other errors have been reported as configuration errors

        // Error fatality depends on the error context: Reconfiguration errors
        // are, like startup ones, DBG_CRITICAL but will never become FATAL.
        if (starting_up && seenErrors <= 10)
            debugs(4, debugLevel, "WARNING: The following configuration error will be fatal in future Squid versions");

        debugs(4, debugLevel, "ERROR: " << BuildErrorPrinter(inputLocation, page_id, msg, near));
    } else {
        throw TexcHere(ToSBuf(BuildErrorPrinter(inputLocation, page_id, msg, near)));
    }
}

/* ErrorPage::BuildErrorPrinter */

std::ostream &
ErrorPage::BuildErrorPrinter::printLocation(std::ostream &os) const {
    if (!inputLocation.isEmpty())
        return os << inputLocation;

    if (page_id < ERR_NONE || page_id >= error_page_count)
        return os << "[error page " << page_id << "]"; // should not happen

    if (page_id < ERR_MAX)
        return os << err_type_str[page_id];

    return os << "deny_info " << ErrorDynamicPages.at(page_id - ERR_MAX)->page_name;
}

std::ostream &
ErrorPage::BuildErrorPrinter::print(std::ostream &os) const {
    printLocation(os) << ": " << msg << " near ";

    // TODO: Add support for prefix printing to Raw
    const size_t maxContextLength = 15; // plus "..."
    if (strlen(near) > maxContextLength) {
        os.write(near, maxContextLength);
        os << "...";
    } else {
        os << near;
    }

    // XXX: We should not be converting (inner) exception to text if we are
    // going to throw again. See "add arbitrary (re)thrower-supplied details"
    // TODO in TextException.h for a long-term in-catcher solution.
    if (std::current_exception())
        os << "\n    additional info: " << CurrentException;

    return os;
}

/// add error page template to the global index
static void
ErrorPage::ImportStaticErrorText(const int page_id, const char *text, const SBuf &inputLocation)
{
    assert(!error_text[page_id]);
    error_text[page_id] = xstrdup(text);
    ValidateStaticError(page_id, inputLocation);
}

/// validate static error page
static void
ErrorPage::ValidateStaticError(const int page_id, const SBuf &inputLocation)
{
    // Supplying nil ALE pointer limits validation to logformat %code
    // recognition by Format::Token::parse(). This is probably desirable
    // because actual %code assembly is slow and should not affect validation
    // when our ALE cannot have any real data (this code is not associated
    // with any real transaction).
    ErrorState anErr(err_type(page_id), Http::scNone, nullptr, nullptr);
    anErr.inputLocation = inputLocation;
    anErr.validate();
}

std::ostream &
operator <<(std::ostream &os, const ErrorState *err)
{
    if (err)
        os << errorPageName(err->page_id);
    else
        os << "[none]";
    return os;
}

