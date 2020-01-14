/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AtStepData.h"
#include "acl/Checklist.h"
#include "base/EnumIterator.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "sbuf/Stream.h"
#include "wordlist.h"

static inline const char *
StepName(const XactionStep xstep)
{
    // keep in sync with XactionStep
    static const char *StepNames[static_cast<int>(XactionStep::enumEnd_)] = {
        "[unknown step]"
        ,"GeneratingCONNECT"
#if USE_OPENSSL
        ,"SslBump1"
        ,"SslBump2"
        ,"SslBump3"
#endif
    };

    assert(XactionStep::enumBegin_ <= xstep && xstep < XactionStep::enumEnd_);
    return StepNames[static_cast<int>(xstep)];
}

static XactionStep
StepValue(const char *name)
{
    assert(name);

    for (const auto step: WholeEnum<XactionStep>()) {
        if (strcasecmp(StepName(step), name) == 0)
            return static_cast<XactionStep>(step);
    }

    throw TextException(ToSBuf("unknown at_step step name: ", name), Here());
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
    while (const auto name = ConfigParser::strtokFile()) {
        const auto step = StepValue(name);
        if (step == XactionStep::unknown)
            throw TextException(ToSBuf("prohibited at_step step name: ", name), Here());
        values.push_back(step);
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

