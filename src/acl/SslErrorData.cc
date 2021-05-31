/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/SslErrorData.h"
#include "security/CertError.h"
#include "ssl/ErrorDetail.h"

ACLSslErrorData::ACLSslErrorData(ACLSslErrorData const &o) :
    values(o.values)
{}

bool
ACLSslErrorData::match(const Security::CertErrors *toFind)
{
    for (const auto *err = toFind; err; err = err->next) {
        if (values.count(err->element.code))
            return true;
    }
    return false;
}

SBufList
ACLSslErrorData::dump() const
{
    SBufList sl;
    for (const auto &e : values) {
        sl.push_back(SBuf(Ssl::GetErrorName(e)));
    }
    return sl;
}

void
ACLSslErrorData::parse()
{
    while (char *t = ConfigParser::strtokFile()) {
        Ssl::ParseErrorString(t, values);
    }
}

ACLSslErrorData *
ACLSslErrorData::clone() const
{
    return new ACLSslErrorData(*this);
}

