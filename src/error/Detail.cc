/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
class NamedErrorDetail: public ErrorDetail
{
public:
    // convert from c-string to SBuf to simplify creation and optimize usage
    /// \param aName must not contain characters that require quoting in access logs or HTML
    explicit NamedErrorDetail(const char *aName): name(aName) {}

    /* ErrorDetail API */
    virtual SBuf brief() const override { return name; }
    virtual SBuf verbose(const HttpRequestPointer &) const override { return name; }

private:
    /// distinguishes us from all other NamedErrorDetail objects
    SBuf name;
};

/* ErrorDetail */

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

