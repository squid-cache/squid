/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "error/Detail.h"
#include "HttpRequest.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

/// details an error by tying it to a uniquely named circumstance
class NamedErrorDetail: public ErrorDetail {
public:
    /// briefly describes the error circumstances
    /// must not contain characters that require quoting in access logs or HTML
    typedef SBuf Name;

    // convert from c-string to SBuf to simplify creation and optimize usage
    explicit NamedErrorDetail(const char *aName): name(aName) {}

    /* ErrorDetail API */
    virtual SBuf brief() const override { return name; }

private:
    /// distinguishes us from all other NamedErrorDetail objects
    Name name;
};

/* ErrorDetail */

SBuf
ErrorDetail::verbose(const HttpRequest::Pointer &) const
{
    return brief();
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetail &detail)
{
    os << detail.brief();
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

/* NamedErrorDetail */

ErrorDetail::Pointer
MakeNamedErrorDetail(const char *name)
{
    return new NamedErrorDetail(name);
}

/* SysErrorDetail */

SBuf
SysErrorDetail::Brief(const int errorNo)
{
    return SysErrorDetail(errorNo).brief();
}

SBuf
SysErrorDetail::brief() const
{
    return ToSBuf("SYSERR=", errorNo); // TODO: Use errno=... instead?
}

SBuf
SysErrorDetail::verbose(const HttpRequest::Pointer &) const
{
    return SBuf(strerror(errorNo));
}

/* ExceptionErrorDetail */

SBuf
ExceptionErrorDetail::brief() const
{
    return ToSBuf("EXCEPTION=", std::hex, exceptionId); // TODO: Use exception=... instead?
}

SBuf
ExceptionErrorDetail::verbose(const HttpRequest::Pointer &) const
{
    return ToSBuf("Exception (ID=", std::hex, exceptionId, ')');
}

