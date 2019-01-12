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
#include "log/forward.h"
#include "http/forward.h"
#include "http/StatusCode.h"
#include "ip/Address.h"
#include "SquidString.h"
/* auth/UserRequest.h is empty unless USE_AUTH is defined */
#include "auth/UserRequest.h"
#if USE_OPENSSL
#include "ssl/ErrorDetail.h"
#endif

#include <memory>

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
 * Also the squid logformat codes supported using the @Squid{%logformat_code}
 * syntax.
 */

class MemBuf;
class StoreEntry;
class wordlist;

/// \ingroup ErrorPageAPI
class ErrorState
{
    CBDATA_CLASS(ErrorState);

public:
    /// Class to handle parsing errors found in error template files.
    /// It just report the found errors to log files, however
    /// it is used as a base class to implement  more complex error
    /// handlers.
    class ErrorHandler {
    public:
        ErrorHandler(int aLevel, SBuf &aLebel, SBuf &aDescription);

        /// do the required actions when an error found
        virtual void handleError(const SBuf &mesg);

        /// \retval the number of reported errors
        int errors() { return errors_; }

        /// Report an error to log files
        void report(const SBuf &mesg);

    protected:
        int errors_ = 0; ///< counts the reported errors
        int level; ///< The debug level to report the error in log files
        SBuf label; ///< A label to use when reporting parse errors

        /// Description of the context where the ErrorHandler is used.
        /// Logged once, before the first error, to report that errors
        /// found at the given context.
        SBuf ctxDescr;
    };

public:
    ErrorState(err_type type, Http::StatusCode, HttpRequest * request, const AccessLogEntryPointer &al);
    ErrorState() = delete; // not implemented.
    ~ErrorState();

    /// Creates a general request forwarding error with the right http_status.
    static ErrorState *NewForwarding(err_type, HttpRequestPointer &, const AccessLogEntryPointer &);

    /**
     * Allocates and initializes an error response
     */
    HttpReply *BuildHttpReply(void);

    /// set error type-specific detail code
    void detailError(int dCode) {detailCode = dCode;}

    /// Sets the ErrorHandler to use when parses templates
    void setErrorHandler(ErrorHandler *handler) {errorHandler_.reset(handler);};

    /**
     * Lowlevel method to convert the given template string and write it
     * to a given MemBuf object.
     * Throws on parse error
     * \param text            The string to be converted
     * \param result          where to write output.
     * \param building_deny_info_url  Whether the text input is a deny info url
     * \param allowRecursion  Whether to convert codes which output may contain codes
     */
    void convertAndWriteTo(const char *text, MemBuf &result, bool building_deny_info_url, bool allowRecursion);

    /// Checks if the text can be parsed correctly.
    static bool ParseCheck(const char *text, bool is_deny_info_url, const char *&err);

    /// True if the text is a URL deny info
    static bool IsDenyInfoUrl(const char *text);

private:
    /**
     * Searches in  a string for the next formating code and return a pointer
     * to it, or a pointer to the end of input string.
     * Return always a non-nil value.
     */
    static const char *NextCode(const char *p);

    /**
     * Locates error page template to be used for this error
     * and constructs the HTML page content from it.
     */
    MemBuf *BuildContent(void);

    /**
     * Convert the given template string into textual output
     * Throws on parse error
     *
     * \param text            The string to be converted
     * \param allowRecursion  Whether to convert codes which output may contain codes
     */
    MemBuf *ConvertText(const char *text, bool allowRecursion);

    /**
     * Generates the Location: header value for a deny_info error page
     * to be used for this error.
     */
    void DenyInfoLocation(const char *name, HttpRequest *request, MemBuf &result);

    /**
     * Map the Error page and deny_info template % codes into textual output.
     *
     * Several of the codes produce blocks of non-URL compatible results.
     * When processing the deny_info location URL they will be skipped.
     *
     * \param token                    The token following % which need to be converted
     * \param building_deny_info_url   Perform special deny_info actions, such as URL-encoding and token skipping.
     * \ allowRecursion   True if the codes which do recursions should converted
     */
    const char *convert(const char *start, bool building_deny_info_url, bool allowRecursion);

    /// Handle the @Squid{%logformat_code} formatting code.
    /// On success updates 'start' to point after the @Squid{}
    /// formatting code and appends the generated string to 'result'.
    /// Throws on parse error.
    void handleLogFormat(const char *&start, MemBuf &result);
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
    Http::StatusCode httpStatus;
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

#if USE_OPENSSL
    Ssl::ErrorDetail *detail = nullptr;
#endif
    /// type-specific detail about the transaction error;
    /// overwrites xerrno; overwritten by detail, if any.
    int detailCode = ERR_DETAIL_NONE;
    AccessLogEntryPointer al;

private:
    // Error handler to use to report errors while parses error pages
    std::unique_ptr<ErrorHandler> errorHandler_;

    static const SBuf LogFormatStart;
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

/// \ingroup ErrorPageAPI
err_type errorReservePageId(const char *page_name);

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

    bool silent; ///< Whether to print error messages on cache.log file or not. It is user defined.

protected:
    /// Used to parse (if parsing required) the template data .
    virtual bool parse() = 0;

    /**
     * Try to load the "page_name" template for a given language "lang"
     * from squid errors directory
     \return true on success false otherwise
     */
    bool tryLoadTemplate(const char *lang);

    SBuf textBuf; ///< A Buffer to store the template
    bool wasLoaded; ///< True if the template data read from disk without any problem
    String errLanguage; ///< The error language of the template.
    String templateName; ///< The name of the template
    err_type templateCode; ///< The internal code for this template.
    SBuf lastTemplateFile; ///< The last used path
};

/// Checks error pages text for syntax errors
class ErrTextValidator {
public:
    ErrTextValidator() {}
    ErrTextValidator(const char *aName) : name_(aName) {}

    /// Setup the current object to handle the checked text as a configuration
    /// file error page formatted string like those can be found in deny_info
    /// configuration parameter.
    /// \par filename the configuration file path
    /// \par lineNo the number of parsed line
    /// \par line the configuration file line
    /// The parameters used to describe the error to the caller
    /// \retval this
    ErrTextValidator &useCfgContext(const char *filename, int lineNo, const char *line);

    /// Setup the current object to handle checked text as a template error
    /// page.
    /// \retval this
    ErrTextValidator &useFileContext(const char *templateFilename);

    /// The debug level to use for debug messages
    /// \retval this
    ErrTextValidator &warn(int level) { warn_ = level; return *this; }

    /// The ErrTextValidator::validate throws on parse errors
    /// \retval this
    ErrTextValidator &throws() { onError_ = doThrow; return *this; }

    /// Report and then ignore parse errors, the ErrTextValidator::validate
    /// returns always true
    /// \retval this
    ErrTextValidator &report() { onError_ = doReport; return *this; }

    /// Check the given error template text for problems. If problems are
    /// found, either throw or just report the problem to cache.log, depending
    /// on whether throws() was called to enable throwing.
    void validate(const char *text);

    /// \return true if the object initialized and can be used to validate text
    bool initialised() { return name_.length() != 0;}
private:
    enum Context {
        CtxUnknown,
        CtxFile, ///< It is used to parse a squid templates
        CtxConfig ///< It is used to parse a text from squid configuration file (eg from deny_info line)
    };
    enum OnError {
        doReport, ///< Just report the error using squid log
        doThrow ///< Reports and then throws on error
    };

    Context ctx = CtxUnknown; ///< The current context type

    /// A name for validator to be used for debugging. It can be the caller
    /// function name or caller class name.
    SBuf name_;

    OnError onError_ = doReport; ///< Action when an error detected
    int warn_ = 3; ///< The debug level to use for error messages
    SBuf ctxFilename; ///< The configuration file or the error page template

    /// The current configuration file line number on CtxConfig context.
    int ctxLineNo_ = 0;

    /// The current configuration file line on CtxConfig context.
    SBuf ctxLine_;
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

