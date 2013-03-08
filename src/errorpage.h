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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef   SQUID_ERRORPAGE_H
#define   SQUID_ERRORPAGE_H

#include "cbdata.h"
#include "comm/forward.h"
#include "err_detail_type.h"
#include "err_type.h"
#include "HttpStatusCode.h"
#include "ip/Address.h"
#include "SquidString.h"
/* auth/UserRequest.h is empty unless USE_AUTH is defined */
#include "auth/UserRequest.h"
#if USE_SSL
#include "ssl/ErrorDetail.h"
#endif

/**
 \defgroup ErrorPageAPI Error Pages API
 \ingroup Components
 \section ErrorPageStringCodes Error Page % codes for text insertion.
 *
 \verbatim
   a - User identity                            x
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
 */

class HttpReply;
class HttpRequest;
class MemBuf;

/// \ingroup ErrorPageAPI
class ErrorState
{
public:
    ErrorState(err_type type, http_status, HttpRequest * request);
    ErrorState(); // not implemented.
    ~ErrorState();

    /**
     * Allocates and initializes an error response
     */
    HttpReply *BuildHttpReply(void);

    /// set error type-specific detail code
    void detailError(int dCode) {detailCode = dCode;}

private:
    /**
     * Locates error page template to be used for this error
     * and constructs the HTML page content from it.
     */
    MemBuf *BuildContent(void);

    /**
     * Convert the given template string into textual output
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
    const char *Convert(char token, bool building_deny_info_url, bool allowRecursion);

    /**
     * CacheManager / Debug dump of the ErrorState object.
     * Writes output into the given MemBuf.
     \retval 0 successful completion.
     */
    int Dump(MemBuf * mb);

public:
    err_type type;
    int page_id;
    char *err_language;
    http_status httpStatus;
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request;
#endif
    HttpRequest *request;
    char *url;
    int xerrno;
    unsigned short port;
    String dnsError; ///< DNS lookup error message
    time_t ttl;

    Ip::Address src_addr;
    char *redirect_url;
    ERCB *callback;
    void *callback_data;

    struct {
        unsigned int flag_cbdata:1;
    } flags;

    struct {
        wordlist *server_msg;
        char *request;
        char *reply;
        char *cwd_msg;
        MemBuf *listing;
    } ftp;

    char *request_hdrs;
    char *err_msg; /* Preformatted error message from the cache */

#if USE_SSL
    Ssl::ErrorDetail *detail;
#endif
    /// type-specific detail about the transaction error;
    /// overwrites xerrno; overwritten by detail, if any.
    int detailCode;
private:
    CBDATA_CLASS2(ErrorState);
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
    bool loadDefault();

    /**
     * Load an error template for a given HTTP request. This function examines the
     * Accept-Language header and select the first available template. If the default
     * template selected (eg because of a "Accept-Language: *"), or not available
     * template found this function return false.
     */
    bool loadFor(HttpRequest *request);

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
    virtual bool parse(const char *buf, int len, bool eof) = 0;

    /**
     * Try to load the "page_name" template for a given language "lang"
     * from squid errors directory
     \return true on success false otherwise
     */
    bool tryLoadTemplate(const char *lang);

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
