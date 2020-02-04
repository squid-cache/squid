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

typedef enum {
    ERR_DETAIL_NONE,
    ERR_DETAIL_START,
    ERR_DETAIL_REDIRECTOR_TIMEDOUT = ERR_DETAIL_START, // External redirector request timed-out
    ERR_DETAIL_CLT_REQMOD_ABORT, // client-facing code detected transaction abort
    ERR_DETAIL_CLT_REQMOD_REQ_BODY, // client-facing code detected REQMOD request body adaptation failure
    ERR_DETAIL_CLT_REQMOD_RESP_BODY, // client-facing code detected REQMOD satisfaction reply body failure
    ERR_DETAIL_SRV_REQMOD_REQ_BODY, // server-facing code detected REQMOD request body abort
    ERR_DETAIL_ICAP_RESPMOD_EARLY, // RESPMOD failed w/o store entry
    ERR_DETAIL_ICAP_RESPMOD_LATE,  // RESPMOD failed with a store entry
    ERR_DETAIL_REQMOD_BLOCK, // REQMOD denied client access
    ERR_DETAIL_RESPMOD_BLOCK_EARLY, // RESPMOD denied client access to HTTP response, before any part of the response was sent
    ERR_DETAIL_RESPMOD_BLOCK_LATE, // RESPMOD denied client access to HTTP response, after [a part of] the response was sent
    ERR_DETAIL_ICAP_XACT_START, // transaction start failure
    ERR_DETAIL_ICAP_XACT_SSL_START, // transaction start failure
    ERR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT, // transaction body consumer gone
    ERR_DETAIL_ICAP_INIT_GONE, // initiator gone
    ERR_DETAIL_ICAP_XACT_CLOSE, // ICAP connection closed unexpectedly
    ERR_DETAIL_ICAP_XACT_OTHER, // other ICAP transaction errors
    ERR_DETAIL_TLS_HELLO_PARSE_ERROR, // Squid TLS handshake parser failed
    ERR_DETAIL_SSL_BUMP_SPLICE, // an SslBump step2 splicing error (XXX: too general)
    ERR_DETAIL_TLS_HANDSHAKE, // TLS negotiation errors
    ERR_DETAIL_EXCEPTION_OTHER, //other errors ( eg std C++ lib errors)
    ERR_DETAIL_SYS, // system error errors, errno
    ERR_DETAIL_EXCEPTION, // Squid exception
    ERR_DETAIL_FTP_ERROR, // FTP errors
    ERR_DETAIL_MAX,
} err_detail_type;

extern const char *err_detail_type_str[];

class ErrorDetail: public RefCountable
{
public:
    typedef RefCount<ErrorDetail> Pointer;

    ErrorDetail(int id): errorDetailId(id) {}
    virtual const char *logCode() {
        if (errorDetailId >= ERR_DETAIL_START && errorDetailId < ERR_DETAIL_MAX)
            return err_detail_type_str[errorDetailId-ERR_DETAIL_START+2];

        return "UNKNOWN";
    }

    /// An error detail string to embed in squid error pages.
    virtual const char *detailString(const HttpRequestPointer &) {return logCode();}

    const int type() {return errorDetailId;}

protected:
    int errorDetailId = 0;
};

class SysErrorDetail: public ErrorDetail {
public:
    SysErrorDetail(int error): ErrorDetail(ERR_DETAIL_SYS), errorNo(error) {}
    virtual const char *logCode() final;
    virtual const char *detailString(const HttpRequestPointer &) final;
private:
    int errorNo;
};

/// offset for exception ID details, for backward compatibility
#define SQUID_EXCEPTION_START_BASE 110000

class ExceptionErrorDetail: public ErrorDetail {
public:
    ExceptionErrorDetail(SourceLocationId id): ErrorDetail(ERR_DETAIL_EXCEPTION), exceptionId(SQUID_EXCEPTION_START_BASE + id) {}
    virtual const char *logCode() final;
private:
    SourceLocationId exceptionId;
};

#endif

