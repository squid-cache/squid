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
#include "wordlist.h"

const char *ACLAtStepData::AtStepValuesStr[] = {
#if USE_OPENSSL
    "SslBump1",
    "SslBump2",
    "SslBump3",
#endif
    "GeneratingCONNECT",
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
ACLAtStepData::match(int toFind)
{
    for (auto it = values.cbegin(); it != values.cend(); ++it) {
        if (*it == toFind)
            return true;
    }
    return false;
}

SBufList
ACLAtStepData::dump() const
{
    SBufList sl;
    for (auto it = values.cbegin(); it != values.cend(); ++it) {
        sl.push_back(SBuf(AtStepStr(*it)));
    }
    return sl;
}

void
ACLAtStepData::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        const auto at = AtStep(t);
        if (at == atStepValuesEnd) {
            debugs(28, DBG_CRITICAL, "FATAL: invalid AtStep step: " << t);
            self_destruct();
        }
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
ACLAtStepData::AtStepStr(int at)
{
    if (at >=0 && at < atStepValuesEnd)
        return AtStepValuesStr[at];
    else
        return "-";
}

int
ACLAtStepData::AtStep(const char *atStr)
{
    for (auto at = 0; at < atStepValuesEnd; ++at)
        if (strcasecmp(atStr, AtStepValuesStr[at]) == 0)
            return at;

    return atStepValuesEnd;
}

