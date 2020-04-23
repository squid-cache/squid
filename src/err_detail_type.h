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
#include "sbuf/forward.h"

/// interface for supplying additional information about a transaction error
class ErrorDetail: public RefCountable
{
public:
    typedef RefCount<ErrorDetail> Pointer;

    virtual ~ErrorDetail() {}

    /// \returns a single "token" summarizing available details
    /// suitable as an access.log field and similar output processed by programs
    virtual SBuf brief() const = 0;

    /// \returns all available details; may be customized for the given request
    /// suitable for error pages and other output meant for human consumption
    /// by default (i.e. if kids do not override), returns brief()
    virtual SBuf verbose(const HttpRequestPointer &) const;
};

/// records the first seen detail; eventually, we might store more than one
inline void
Update(ErrorDetail::Pointer &storage, const ErrorDetail::Pointer &latest)
{
    if (!storage)
        storage = latest; // may still be nil
}

/// system call error detail based on standard errno(3)/strerror(3) APIs
class SysErrorDetail: public ErrorDetail {
    MEMPROXY_CLASS(SysErrorDetail);

public:
    /// \returns a pointer to a SysErrorDetail instance (or nil for lost errnos)
    static ErrorDetail::Pointer NewIfAny(const int errorNo)
    {
        // we could optimize by caching results for (frequently used?) errnos
        return errorNo ? new SysErrorDetail(errorNo) : nullptr;
    }

    static SBuf Brief(int errorNo);

    /* ErrorDetail API */
    virtual SBuf brief() const final;
    virtual SBuf verbose(const HttpRequestPointer &) const final;

private:
    // hidden by NewIfAny() to avoid creating SysErrorDetail from zero errno
    explicit SysErrorDetail(const int anErrorNo): errorNo(anErrorNo) {}

    int errorNo; ///< errno(1) set by the last failed system call or equivalent
};

/// offset for exception ID details, for backward compatibility
#define SQUID_EXCEPTION_START_BASE 110000

/// Squid exception error details. It stores exceptions ids which can
/// examined with the calc-must-ids.sh squid utility to find the cause
/// of the error.
class ExceptionErrorDetail: public ErrorDetail {
    MEMPROXY_CLASS(ExceptionErrorDetail);

public:
    explicit ExceptionErrorDetail(const SourceLocationId id): exceptionId(SQUID_EXCEPTION_START_BASE + id) {}

    /* ErrorDetail API */
    virtual SBuf brief() const final;
    virtual SBuf verbose(const HttpRequestPointer &) const final;

private:
    SourceLocationId exceptionId; ///< the exception id
};

/// dump the given ErrorDetail (for debugging)
std::ostream &operator <<(std::ostream &os, const ErrorDetail &);

/// dump the given ErrorDetail pointer which may be nil (for debugging)
std::ostream &operator <<(std::ostream &os, const ErrorDetail::Pointer &);

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

/// tunneling after error failed for an unknown reason
extern const ErrorDetail::Pointer ERR_DETAIL_TUNNEL_ON_ERROR;

/// an SslBump step2 splicing error (XXX: too general)
extern const ErrorDetail::Pointer ERR_DETAIL_SSL_BUMP_SPLICE;

/// TLS parsing or negotiation failure at the beginning of a TLS connection
extern const ErrorDetail::Pointer ERR_DETAIL_TLS_HANDSHAKE;

/// other errors that lead to exceptions caught by transactions
/// (e.g., exceptions thrown by C++ STL)
extern const ErrorDetail::Pointer ERR_DETAIL_EXCEPTION_OTHER;

#endif

