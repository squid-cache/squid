/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 04    Error Generation */

#ifndef   SQUID_ERRORPAGE_H
#define   SQUID_ERRORPAGE_H

#include "cbdata.h"
#include "comm/forward.h"
#include "err_detail_type.h"
#include "err_type.h"
#include "http/forward.h"
#include "http/StatusCode.h"
#include "ip/Address.h"
#include "log/forward.h"
#include "sbuf/SBuf.h"
#include "SquidString.h"
/* auth/UserRequest.h is empty unless USE_AUTH is defined */
#include "auth/UserRequest.h"
#if USE_OPENSSL
#include "ssl/ErrorDetail.h"
#endif

/// error page callback
typedef void ERCB(int fd, void *, size_t);

/**
 \defgroup ErrorPageAPI Error Pages API
 \ingroup Components
 \section ErrorPageStringCodes Error Page % codes for text insertion.
 *
 \verbatim
   a - User identity                            x
   A - Local listening IP address               x
   B - URL with FTP %2f hack                    x
   c - Squid error code                         x
   d - seconds elapsed since request received   x
   D - Error details                            x
   e - errno                                    x
   E - strerror()                               x
   f - FTP request line                         x
   F - FTP reply line                           x
   g - FTP server message                       x
   h - cache hostname                           x
   H - server host name                         x
   i - client IP address                        x
   I - server IP address                        x
   l - HREF link for CSS stylesheet inclusion   x
   L - HREF link for more info/contact          x
   M - Request Method                           x
   m - Error message returned by auth helper    x
   o - Message returned external acl helper     x
   p - URL port #                               x
   P - Protocol                                 x
   R - Full HTTP Request                        x
   S - squid signature from ERR_SIGNATURE       x
   s - caching proxy software with version      x
   t - local time                               x
   T - UTC                                      x
   U - URL without password                     x
   u - URL with password                        x
   w - cachemgr email address                   x
   W - error data (to be included in the mailto links)
   x - error name                               x
   z - dns server error message                 x
   Z - Preformatted error message               x
 \endverbatim
 *
 * Plus logformat %codes embedded using @Squid{%logformat_code} syntax.
 */

class MemBuf;
class StoreEntry;
class wordlist;

namespace ErrorPage {

class Build;

} // namespace ErrorPage

/// \ingroup ErrorPageAPI
class ErrorState
{
    CBDATA_CLASS(ErrorState);

public:
    /// creates an error of type other than ERR_RELAY_REMOTE
    ErrorState(err_type type, Http::StatusCode, HttpRequest * request, const AccessLogEntryPointer &al);
    ErrorState() = delete; // not implemented.

    /// creates an ERR_RELAY_REMOTE error
    ErrorState(HttpRequest * request, HttpReply *);

    ~ErrorState();

    /// Creates a general request forwarding error with the right http_status.
    static ErrorState *NewForwarding(err_type, HttpRequestPointer &, const AccessLogEntryPointer &);

    /**
     * Allocates and initializes an error response
     */
    HttpReply *BuildHttpReply(void);

    /// set error type-specific detail code
    void detailError(int dCode) {detailCode = dCode;}

    /// ensures that a future BuildHttpReply() is likely to succeed
    void validate();

    /// the source of the error template (for reporting purposes)
    SBuf inputLocation;

private:
    typedef ErrorPage::Build Build;

    /// initializations shared by public constructors
    explicit ErrorState(err_type type);

    /// locates the right error page template for this error and compiles it
    SBuf buildBody();

    /// compiles error page or error detail template (i.e. anything but deny_url)
    /// \param input  the template text to be compiled
    /// \param allowRecursion  whether to compile %codes which produce %codes
    SBuf compileBody(const char *text, bool allowRecursion);

    /// compile a single-letter %code like %D
    void compileLegacyCode(Build &build);

    /// compile @Squid{%code} sequence containing a single logformat %code
    void compileLogformatCode(Build &build);

    /// replaces all legacy and logformat %codes in the given input
    /// \param input  the template text to be converted
    /// \param building_deny_info_url  whether input is a deny_info URL parameter
    /// \param allowRecursion  whether to compile %codes which produce %codes
    /// \returns the given input with all %codes substituted
    SBuf compile(const char *input, bool building_deny_info_url, bool allowRecursion);

    /// React to a compile() error, throwing if buildContext allows.
    /// \param msg description of what went wrong
    /// \param near approximate start of the problematic input
    void noteBuildError(const char *msg, const char *near) {
        noteBuildError_(msg, near, false);
    }

    /// Note a compile() error but do not throw for backwards
    /// compatibility with older configurations that may have such errors.
    /// Should eventually be replaced with noteBuildError().
    /// \param msg description of what went wrong
    /// \param near approximate start of the problematic input
    void bypassBuildErrorXXX(const char *msg, const char *near) {
        noteBuildError_(msg, near, true);
    }

    /**
     * CacheManager / Debug dump of the ErrorState object.
     * Writes output into the given MemBuf.
     \retval 0 successful completion.
     */
    int Dump(MemBuf * mb);

public:
    err_type type = ERR_NONE;
    int page_id = ERR_NONE;
    char *err_language = nullptr;
    Http::StatusCode httpStatus = Http::scNone;
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request;
#endif
    HttpRequestPointer request;
    char *url = nullptr;
    int xerrno = 0;
    unsigned short port = 0;
    String dnsError; ///< DNS lookup error message
    time_t ttl = 0;

    Ip::Address src_addr;
    char *redirect_url = nullptr;
    ERCB *callback;
    void *callback_data = nullptr;

    struct {
        wordlist *server_msg = nullptr;
        char *request = nullptr;
        char *reply = nullptr;
        char *cwd_msg = nullptr;
        MemBuf *listing = nullptr;
    } ftp;

    char *request_hdrs = nullptr;
    char *err_msg = nullptr; /* Preformatted error message from the cache */

    AccessLogEntryPointer ale; ///< transaction details (or nil)

#if USE_OPENSSL
    Ssl::ErrorDetail *detail = nullptr;
#endif
    /// type-specific detail about the transaction error;
    /// overwrites xerrno; overwritten by detail, if any.
    int detailCode = ERR_DETAIL_NONE;

    HttpReplyPointer response_;

private:
    void noteBuildError_(const char *msg, const char *near, const bool forceBypass);

    static const SBuf LogformatMagic; ///< marks each embedded logformat entry
};

/**
 \ingroup ErrorPageAPI
 *
 * This function finds the error messages formats, and stores
 * them in error_text[]
 *
 \par Global effects:
 *            error_text[] - is modified
 */
void errorInitialize(void);

/// \ingroup ErrorPageAPI
void errorClean(void);

/**
 * \ingroup ErrorPageAPI
 *
 * This function generates a error page from the info contained
 * by err and then sends it to the client.
 * The callback function errorSendComplete() is called after
 * the page has been written to the client (clientConn).
 * errorSendComplete() deallocates err.  We need to add
 * err to the cbdata because comm_write() requires it
 * for all callback data pointers.
 *
 \note normally errorSend() should only be called from
 *     routines in ssl.c and pass.c, where we don't have any
 *     StoreEntry's.  In client_side.c we must allocate a StoreEntry
 *     for errors and use errorAppendEntry() to account for
 *     persistent/pipeline connections.
 *
 \param clientConn  socket where page object is to be written
 \param err         This object is destroyed after use in this function.
 */
void errorSend(const Comm::ConnectionPointer &conn, ErrorState *err);

/**
 \ingroup ErrorPageAPI
 *
 * This function generates a error page from the info contained
 * by err and then stores the text in the specified store
 * entry.
 * This function should only be called by "server
 * side routines" which need to communicate errors to the
 * client side.  It should also be called from client_side.c
 * because we now support persistent connections, and
 * cannot assume that we can immediately write to the socket
 * for an error.
 *
 \param entry   ??
 \param err     This object is destroyed after use in this function.
 */
void errorAppendEntry(StoreEntry *entry, ErrorState *err);

/// allocates a new slot for the error page
err_type errorReservePageId(const char *page_name, const SBuf &cfgLocation);

const char *errorPageName(int pageId); ///< error ID to string

/**
 \ingroup ErrorPageAPI
 *
 * loads text templates used for error pages and details;
 * supports translation of templates
 */
class TemplateFile
{
public:
    TemplateFile(const char *name, const err_type code);
    virtual ~TemplateFile() {}

    /// return true if the data loaded from disk without any problem
    bool loaded() const {return wasLoaded;}

    /**
     * Load the page_name template from a file which  probably exist at:
     *  (a) admin specified custom directory (error_directory)
     *  (b) default language translation directory (error_default_language)
     *  (c) English sub-directory where errors should ALWAYS exist
     * If all of the above fail, setDefault() is called.
     */
    void loadDefault();

    /**
     * Load an error template for a given HTTP request. This function examines the
     * Accept-Language header and select the first available template. If the default
     * template selected (eg because of a "Accept-Language: *"), or not available
     * template found this function return false.
     */
    bool loadFor(const HttpRequest *request);

    /**
     * Load the file given by "path". It uses the "parse()" method.
     * On success return true and sets the "defined" member
     */
    bool loadFromFile(const char *path);

    /// The language used for the template
    const char *language() {return errLanguage.termedBuf();}

    SBuf filename; ///< where the template was loaded from

    bool silent; ///< Whether to print error messages on cache.log file or not. It is user defined.

protected:
    /// post-process the loaded template
    virtual bool parse() { return true; }

    /// recover from loadDefault() failure to load or parse() a template
    virtual void setDefault() {}

    /**
     * Try to load the "page_name" template for a given language "lang"
     * from squid errors directory
     \return true on success false otherwise
     */
    bool tryLoadTemplate(const char *lang);

    SBuf template_; ///< raw template contents
    bool wasLoaded; ///< True if the template data read from disk without any problem
    String errLanguage; ///< The error language of the template.
    String templateName; ///< The name of the template
    err_type templateCode; ///< The internal code for this template.
};

/**
 * Parses the Accept-Language header value and return one language item on
 * each call.
 * Will ignore any whitespace, q-values, and detectably invalid language
 * codes in the header.
 *
 * \param hdr is the Accept-Language header value
 * \param lang a buffer to store parsed language code in
 * \param langlen the length of the lang buffer
 * \param pos is used to store the offset state of parsing. Must be "0" on first call.
 *            Will be altered to point at the start of next field-value.
 * \return true if something looking like a language token has been placed in lang, false otherwise
 */
bool strHdrAcptLangGetItem(const String &hdr, char *lang, int langLen, size_t &pos);

#endif /* SQUID_ERRORPAGE_H */

