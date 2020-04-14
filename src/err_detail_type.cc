/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "err_detail_type.h"
#include "HttpRequest.h"

/// details errors based on a hard-coded list of error circumstances
class EnumeratedErrorDetail: public ErrorDetail {
public:
    /// briefly describes error circumstances
    /// must not contain characters that require quoting in access logs or HTML
    typedef const char *Name;

    EnumeratedErrorDetail(const Name aName): name(aName) {}

    /* ErrorDetail API */
    virtual const char *logCode() const final { return name; }

private:
    /// distinguishes us from all other EnumeratedErrorDetail objects
    Name name;
};

const ErrorDetail::Pointer ERR_DETAIL_NONE = nullptr;
const ErrorDetail::Pointer ERR_DETAIL_REDIRECTOR_TIMEDOUT = new EnumeratedErrorDetail("REDIRECTOR_TIMEDOUT");
const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_ABORT = new EnumeratedErrorDetail("CLT_REQMOD_ABORT");
const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_REQ_BODY = new EnumeratedErrorDetail("CLT_REQMOD_REQ_BODY");
const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_RESP_BODY = new EnumeratedErrorDetail("CLT_REQMOD_RESP_BODY");
const ErrorDetail::Pointer ERR_DETAIL_SRV_REQMOD_REQ_BODY = new EnumeratedErrorDetail("SRV_REQMOD_REQ_BODY");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_RESPMOD_EARLY = new EnumeratedErrorDetail("ICAP_RESPMOD_EARLY");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_RESPMOD_LATE = new EnumeratedErrorDetail("ICAP_RESPMOD_LATE");
const ErrorDetail::Pointer ERR_DETAIL_REQMOD_BLOCK = new EnumeratedErrorDetail("REQMOD_BLOCK");
const ErrorDetail::Pointer ERR_DETAIL_RESPMOD_BLOCK_EARLY = new EnumeratedErrorDetail("RESPMOD_BLOCK_EARLY");
const ErrorDetail::Pointer ERR_DETAIL_RESPMOD_BLOCK_LATE = new EnumeratedErrorDetail("RESPMOD_BLOCK_LATE");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_START = new EnumeratedErrorDetail("ICAP_XACT_START");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_SSL_START = new EnumeratedErrorDetail("ICAP_XACT_SSL_START");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT = new EnumeratedErrorDetail("ICAP_XACT_BODY_CONSUMER_ABORT");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_INIT_GONE = new EnumeratedErrorDetail("ICAP_INIT_GONE");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_CLOSE = new EnumeratedErrorDetail("ICAP_XACT_CLOSE");
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_OTHER = new EnumeratedErrorDetail("ICAP_XACT_OTHER");
const ErrorDetail::Pointer ERR_DETAIL_BUFFER = new EnumeratedErrorDetail("BUFFER");
const ErrorDetail::Pointer ERR_DETAIL_TUNNEL_ON_ERROR = new EnumeratedErrorDetail("TUNNEL_ON_ERROR");
const ErrorDetail::Pointer ERR_DETAIL_TLS_HELLO_PARSE_ERROR = new EnumeratedErrorDetail("TLS_HELLO_PARSE_ERROR");
const ErrorDetail::Pointer ERR_DETAIL_SSL_BUMP_SPLICE = new EnumeratedErrorDetail("SSL_BUMP_SPLICE");
const ErrorDetail::Pointer ERR_DETAIL_TLS_HANDSHAKE = new EnumeratedErrorDetail("TLS_HANDSHAKE");
const ErrorDetail::Pointer ERR_DETAIL_EXCEPTION_OTHER = new EnumeratedErrorDetail("EXCEPTION_OTHER");

const char *
ErrorDetail::detailString(const HttpRequest::Pointer &) const
{
    return logCode();
}

const char *
SysErrorDetail::logCode() const
{
    static char sbuf[512];
    snprintf(sbuf, sizeof(sbuf), "SYSERR=%d", errorNo);
    return sbuf;
}

const char *
SysErrorDetail::detailString(const HttpRequest::Pointer &) const
{
    return strerror(errorNo);
}

const char *
ExceptionErrorDetail::logCode() const
{
    static char sbuf[512];
    snprintf(sbuf, sizeof(sbuf), "EXCEPTION=0x%X", exceptionId);
    return sbuf;
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetail &detail)
{
    os << detail.logCode();
    return os;
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetail::Pointer &detail)
{
    if (detail)
        os << *detail;
    else
        os << "[no details]";
    return os;
}
