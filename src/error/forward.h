/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ERROR_FORWARD_H
#define _SQUID_SRC_ERROR_FORWARD_H

#include "base/forward.h"

typedef enum {
    ERR_NONE,

    /* Access Permission Errors.  Prefix new with ERR_ACCESS_ */
    ERR_ACCESS_DENIED,
    ERR_CACHE_ACCESS_DENIED,
    ERR_CACHE_MGR_ACCESS_DENIED,
    ERR_FORWARDING_DENIED,
    ERR_NO_RELAY,
    ERR_CANNOT_FORWARD,

    /* TCP Errors. */
    ERR_READ_TIMEOUT,
    ERR_LIFETIME_EXP,
    ERR_READ_ERROR,
    ERR_WRITE_ERROR,
    ERR_CONNECT_FAIL,
    ERR_SECURE_CONNECT_FAIL,
    ERR_SOCKET_FAILURE,

    /* DNS Errors */
    ERR_DNS_FAIL,
    ERR_URN_RESOLVE,

    /* HTTP Errors */
    ERR_ONLY_IF_CACHED_MISS,    /* failure to satisfy only-if-cached request */
    ERR_TOO_BIG,
    ERR_INVALID_RESP,
    ERR_UNSUP_HTTPVERSION,     /* HTTP version is not supported */
    ERR_INVALID_REQ,
    ERR_UNSUP_REQ,
    ERR_INVALID_URL,
    ERR_ZERO_SIZE_OBJECT,
    ERR_PRECONDITION_FAILED,
    ERR_CONFLICT_HOST,

    /* FTP Errors */
    ERR_FTP_DISABLED,
    ERR_FTP_UNAVAILABLE,
    ERR_FTP_FAILURE,
    ERR_FTP_PUT_ERROR,
    ERR_FTP_NOT_FOUND,
    ERR_FTP_FORBIDDEN,
    ERR_FTP_PUT_CREATED,        /* !error,a note that the file was created */
    ERR_FTP_PUT_MODIFIED,       /* modified, !created */

    /* ESI Errors */
    ERR_ESI,                    /* Failure to perform ESI processing */

    /* ICAP Errors */
    ERR_ICAP_FAILURE,

    /* Squid problem */
    ERR_GATEWAY_FAILURE,

    /* Special Cases */
    ERR_DIR_LISTING,            /* Display of remote directory (FTP, Gopher) */
    ERR_SQUID_SIGNATURE,        /* not really an error */
    ERR_SHUTTING_DOWN,
    ERR_PROTOCOL_UNKNOWN,

    // NOTE: error types defined below TCP_RESET are optional and do not generate
    //       a log warning if the files are missing
    TCP_RESET,                  // Send TCP RST packet instead of error page

    ERR_CLIENT_GONE, // No client to send the error page to
    ERR_SECURE_ACCEPT_FAIL, // Rejects the SSL connection intead of error page
    ERR_REQUEST_START_TIMEOUT, // Aborts the connection instead of error page
    ERR_REQUEST_PARSE_TIMEOUT, // Aborts the connection instead of error page
    ERR_RELAY_REMOTE, // Sends server reply instead of error page

    /* Cache Manager GUI can install a manager index/home page */
    MGR_INDEX,

    ERR_MAX
} err_type;

class Error;
class ErrorDetail;

typedef RefCount<ErrorDetail> ErrorDetailPointer;

#endif /* _SQUID_SRC_ERROR_FORWARD_H */

