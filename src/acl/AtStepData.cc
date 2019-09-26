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
static const char *StepNames[] = {
    "",
    "GeneratingCONNECT",
#if USE_OPENSSL
    "SslBump1",
    "SslBump2",
    "SslBump3",
#endif
    nullptr // XXX: Why do we need an entry for xstepValuesEnd?
};

static const char *
StepName(XactionStep xstep)
{
    // XXX: [0] has empty name
    return (0 <= xstep && xstep < xstepValuesEnd) ? StepNames[xstep] : "-";
}

static XactionStep
StepValue(const char *name)
{
    assert(name);

    // XXX: [0] has empty name
    for (auto step = 0; step < xstepValuesEnd; ++step) {
        if (strcasecmp(StepNames[step], name) == 0)
            return static_cast<XactionStep>(step);
    }

    throw TextException(ToSBuf("invalid at_step step name: ", name), Here());
}

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
    const auto found = std::find(values.cbegin(), values.cend(), toFind);
    return (found != values.cend());
}

SBufList
ACLAtStepData::dump() const
{
    SBufList sl;
    for (const auto value : values)
        sl.push_back(SBuf(StepName(value)));
    return sl;
}

void
ACLAtStepData::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        values.push_back(StepValue(t));
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
