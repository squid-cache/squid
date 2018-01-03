/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/HasComponentData.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "sbuf/Algorithms.h"

const SBuf ACLHasComponentData::RequestStr("request");
const SBuf ACLHasComponentData::ResponseStr("response");
const SBuf ACLHasComponentData::AleStr("ALE");

ACLHasComponentData::ACLHasComponentData()
    : componentMethods(coEnd, nullptr)
{ }

void
ACLHasComponentData::parse()
{
    const char *tok = ConfigParser::NextToken();
    if (!tok) {
        debugs(28, DBG_CRITICAL, "FATAL: \"has\" acl argument missing");
        self_destruct();
        return;
    }
    if (ConfigParser::PeekAtToken()) {
        debugs(28, DBG_CRITICAL, "FATAL: multiple components not supported for \"has\" acl");
        self_destruct();
        return;
    }
    parseComponent(tok);
}

bool
ACLHasComponentData::match(ACLChecklist *checklist)
{
    for (const auto method: componentMethods)
        if (method && (checklist->*method)())
            return true;
    return false;
}

SBufList
ACLHasComponentData::dump() const
{
    SBufList sl;
    if (componentMethods.at(coRequest))
        sl.push_back(RequestStr);
    if (componentMethods.at(coResponse))
        sl.push_back(ResponseStr);
    if (componentMethods.at(coAle))
        sl.push_back(AleStr);
    return sl;
}

void
ACLHasComponentData::parseComponent(const char *token)
{
    if (RequestStr.cmp(token) == 0)
        componentMethods[coRequest] = &ACLChecklist::hasRequest;
    else if (ResponseStr.cmp(token) == 0)
        componentMethods[coResponse] = &ACLChecklist::hasReply;
    else if (AleStr.cmp(token) == 0)
        componentMethods[coAle] = &ACLChecklist::hasAle;
    else {
        debugs(28, DBG_CRITICAL, "FATAL: unsupported component '" << token << "' for 'has' acl");
        self_destruct();
    }
}

ACLData<ACLChecklist *> *
ACLHasComponentData::clone() const
{
    return new ACLHasComponentData(*this);
}

