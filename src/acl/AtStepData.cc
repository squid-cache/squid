/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AtStepData.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "sbuf/Stream.h"
#include "wordlist.h"

// keep in sync with XactionStep
const char *ACLAtStepData::AtStepValuesStr[] = {
    "",
    "GeneratingCONNECT",
#if USE_OPENSSL
    "SslBump1",
    "SslBump2",
    "SslBump3",
#endif
    nullptr
};

ACLAtStepData::ACLAtStepData()
{}

ACLAtStepData::ACLAtStepData(ACLAtStepData const &old)
{
    values.assign(old.values.begin(), old.values.end());
}

ACLAtStepData::~ACLAtStepData()
{
}

bool
ACLAtStepData::match(XactionStep toFind)
{
    auto found = std::find(values.cbegin(), values.cend(), toFind);
    return (found != values.cend());
}

SBufList
ACLAtStepData::dump() const
{
    SBufList sl;
    for (const auto value : values)
        sl.push_back(SBuf(AtStepStr(value)));
    return sl;
}

void
ACLAtStepData::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        const auto at = AtStep(t); // throws on error
        values.push_back(at);
    }
}

bool
ACLAtStepData::empty() const
{
    return values.empty();
}

ACLAtStepData *
ACLAtStepData::clone() const
{
    return new ACLAtStepData(*this);
}

const char *
ACLAtStepData::AtStepStr(XactionStep at)
{
    if (0 <= at && at < xstepValuesEnd)
        return AtStepValuesStr[at];
    else
        return "-";
}

XactionStep
ACLAtStepData::AtStep(const char *atStr)
{
    for (auto at = 0; at < xstepValuesEnd; ++at)
        if (strcasecmp(atStr, AtStepValuesStr[at]) == 0)
            return static_cast<XactionStep>(at);

    throw TexcHere(ToSBuf("invalid AtStep step: ", atStr));
}

