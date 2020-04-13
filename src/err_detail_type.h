/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_ERR_DETAIL_H
#define  _SQUID_ERR_DETAIL_H

#include "base/Here.h"
#include "base/RefCount.h"
#include "http/forward.h"
#include "mem/forward.h"

typedef enum {
    ERROR_DETAIL_NONE,
    ERR_DETAIL_START,
    ERROR_DETAIL_REDIRECTOR_TIMEDOUT = ERR_DETAIL_START, // External redirector request timed-out
    ERROR_DETAIL_CLT_REQMOD_ABORT, // client-facing code detected transaction abort
    ERROR_DETAIL_CLT_REQMOD_REQ_BODY, // client-facing code detected REQMOD request body adaptation failure
    ERROR_DETAIL_CLT_REQMOD_RESP_BODY, // client-facing code detected REQMOD satisfaction reply body failure
    ERROR_DETAIL_SRV_REQMOD_REQ_BODY, // server-facing code detected REQMOD request body abort
    ERROR_DETAIL_ICAP_RESPMOD_EARLY, // RESPMOD failed w/o store entry
    ERROR_DETAIL_ICAP_RESPMOD_LATE,  // RESPMOD failed with a store entry
    ERROR_DETAIL_REQMOD_BLOCK, // REQMOD denied client access
    ERROR_DETAIL_RESPMOD_BLOCK_EARLY, // RESPMOD denied client access to HTTP response, before any part of the response was sent
    ERROR_DETAIL_RESPMOD_BLOCK_LATE, // RESPMOD denied client access to HTTP response, after [a part of] the response was sent
    ERROR_DETAIL_ICAP_XACT_START, // transaction start failure
    ERROR_DETAIL_ICAP_XACT_SSL_START, // transaction start failure
    ERROR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT, // transaction body consumer gone
    ERROR_DETAIL_ICAP_INIT_GONE, // initiator gone
    ERROR_DETAIL_ICAP_XACT_CLOSE, // ICAP connection closed unexpectedly
    ERROR_DETAIL_ICAP_XACT_OTHER, // other ICAP transaction errors
    ERROR_DETAIL_BUFFER,  // Buffering issues
    ERROR_DETAIL_TUNNEL_ON_ERROR, // Tunneling after error failed for an unknown reason
    ERROR_DETAIL_TLS_HELLO_PARSE_ERROR, // Squid TLS handshake parser failed
    ERROR_DETAIL_SSL_BUMP_SPLICE, // an SslBump step2 splicing error (XXX: too general)
    ERROR_DETAIL_TLS_HANDSHAKE, // TLS negotiation errors
    ERROR_DETAIL_EXCEPTION_OTHER, //other errors ( eg std C++ lib errors)
    ERROR_DETAIL_SYS, // system errors reported via errno and such
    ERROR_DETAIL_EXCEPTION, // Squid exception
    ERROR_DETAIL_FTP_ERROR, // FTP errors
    ERR_DETAIL_MAX,
} err_detail_type;

/// Holds general error details for access logging and presentation
/// in error pages
class ErrorDetail: public RefCountable
{
    MEMPROXY_CLASS(ErrorDetail);
public:
    typedef RefCount<ErrorDetail> Pointer;

    ErrorDetail(err_detail_type id): errorDetailId(id) {}

    /// \returns a short string code for use with access logs
    virtual const char *logCode();
    /// \return an error detail string to embed in squid error pages.
    virtual const char *detailString(const HttpRequestPointer &);

    const err_detail_type type() {return errorDetailId;}

protected:
    err_detail_type errorDetailId = ERROR_DETAIL_NONE;
};

/// Holds system error details. It is based on errno/strerror
class SysErrorDetail: public ErrorDetail {
    MEMPROXY_CLASS(SysErrorDetail);
public:
    SysErrorDetail(int error): ErrorDetail(ERROR_DETAIL_SYS), errorNo(error) {}

    // ErrorDetail API

    /// \returns a short string in the form SYSERR=XXX where XXX is the errno
    virtual const char *logCode() final;
    /// \returns an strerror based string
    virtual const char *detailString(const HttpRequestPointer &) final;

private:
    int errorNo; ///< the system errno
};

/// offset for exception ID details, for backward compatibility
#define SQUID_EXCEPTION_START_BASE 110000

/// Squid exception error details. It stores exceptions ids which can
/// examined with the calc-must-ids.sh squid utility to find the cause
/// of the error.
class ExceptionErrorDetail: public ErrorDetail {
    MEMPROXY_CLASS(ExceptionErrorDetail);
public:
    ExceptionErrorDetail(const SourceLocationId id): ErrorDetail(ERROR_DETAIL_EXCEPTION), exceptionId(SQUID_EXCEPTION_START_BASE + id) {}

    // ErrorDetail API

    /// \returns a short string in the form EXCEPTION=0xXXXXXX
    virtual const char *logCode() final;

private:
    SourceLocationId exceptionId; ///< the exception id
};

/* pre-created error globals that reduce common error handling overheads */

/// an absent error detail -- a nil pointer
extern const ErrorDetail::Pointer ERR_DETAIL_NONE;

/// external redirector request timed-out
extern const ErrorDetail::Pointer ERR_DETAIL_REDIRECTOR_TIMEDOUT;

/// client-facing code detected transaction abort
extern const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_ABORT;

/// client-facing code detected REQMOD request body adaptation failure
extern const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_REQ_BODY;

/// client-facing code detected REQMOD satisfaction reply body failure
extern const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_RESP_BODY;

/// server-facing code detected REQMOD request body abort
extern const ErrorDetail::Pointer ERR_DETAIL_SRV_REQMOD_REQ_BODY;

/// RESPMOD failed w/o store entry
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_RESPMOD_EARLY;

/// RESPMOD failed with a store entry
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_RESPMOD_LATE;

/// REQMOD denied client access
extern const ErrorDetail::Pointer ERR_DETAIL_REQMOD_BLOCK;

/// RESPMOD denied client access to HTTP response, before any part of the response was sent
extern const ErrorDetail::Pointer ERR_DETAIL_RESPMOD_BLOCK_EARLY;

/// RESPMOD denied client access to HTTP response, after [a part of] the response was sent
extern const ErrorDetail::Pointer ERR_DETAIL_RESPMOD_BLOCK_LATE;

/// transaction start failure
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_START;

/// transaction start failure
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_SSL_START;

/// transaction body consumer gone
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT;

/// initiator gone
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_INIT_GONE;

/// ICAP connection closed unexpectedly
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_CLOSE;

/// other ICAP transaction errors
extern const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_OTHER;

/// buffering issues
extern const ErrorDetail::Pointer ERR_DETAIL_BUFFER;

/// tunneling after error failed for an unknown reason
extern const ErrorDetail::Pointer ERR_DETAIL_TUNNEL_ON_ERROR;

/// Squid TLS handshake parser failed
extern const ErrorDetail::Pointer ERR_DETAIL_TLS_HELLO_PARSE_ERROR;

/// an SslBump step2 splicing error (XXX: too general)
extern const ErrorDetail::Pointer ERR_DETAIL_SSL_BUMP_SPLICE;

/// TLS negotiation errors
extern const ErrorDetail::Pointer ERR_DETAIL_TLS_HANDSHAKE;

/// other errors that lead to exceptions caught by transactions
/// (e.g., exceptions thrown by C++ STL)
extern const ErrorDetail::Pointer ERR_DETAIL_EXCEPTION_OTHER;

/// Squid exception
extern const ErrorDetail::Pointer ERR_DETAIL_EXCEPTION;

/// FTP errors
extern const ErrorDetail::Pointer ERR_DETAIL_FTP_ERROR;

#endif

