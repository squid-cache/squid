/*
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef   SQUID_ERRORPAGE_H
#define   SQUID_ERRORPAGE_H

#include "squid.h"
#include "cbdata.h"
#include "ip/IpAddress.h"

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
   z - dns server error message                 x
   Z - Preformatted error message               x
 \endverbatim
 */

class AuthUserRequest;
class HttpReply;
class MemBuf;

/// \ingroup ErrorPageAPI
class ErrorState
{
public:
    /**
     * Allocates and initializes an error response
     */
    HttpReply *BuildHttpReply(void);

private:
    /**
     * Locates error page template to be used for this error
     * and constructs the HTML page content from it.
     */
    MemBuf *BuildContent(void);

    /**
     * Convert an error template into an error page.
     */
    const char *Convert(char token);

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
    AuthUserRequest *auth_user_request;
    HttpRequest *request;
    char *url;
    int xerrno;
    u_short port;
    String dnsError; ///< DNS lookup error message
    time_t ttl;

    IpAddress src_addr;
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
    } ftp;

    char *request_hdrs;
    char *err_msg; /* Preformatted error message from the cache */

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
SQUIDCEXTERN void errorInitialize(void);

/// \ingroup ErrorPageAPI
SQUIDCEXTERN void errorClean(void);

/**
 \ingroup ErrorPageAPI
 *
 * This function generates a error page from the info contained
 * by err and then sends it to the client.
 * The callback function errorSendComplete() is called after
 * the page has been written to the client socket (fd).
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
 \param fd      socket where page object is to be written
 \param err     This object is destroyed after use in this function.
 */
SQUIDCEXTERN void errorSend(int fd, ErrorState *err);

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
SQUIDCEXTERN void errorAppendEntry(StoreEntry *entry, ErrorState *err);

/// \ingroup ErrorPageAPI
SQUIDCEXTERN void errorStateFree(ErrorState * err);

/// \ingroup ErrorPageAPI
SQUIDCEXTERN err_type errorReservePageId(const char *page_name);

/**
 \ingroup ErrorPageAPI
 *
 * This function creates a ErrorState object.
 */
SQUIDCEXTERN ErrorState *errorCon(err_type type, http_status, HttpRequest * request);

#endif /* SQUID_ERRORPAGE_H */
