/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/HasComponentData.h"
#include "cache_cf.h"
#include "cfg/Exceptions.h"
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
    const auto tok = ConfigParser::strtokFile();
    if (!tok)
        throw Cfg::FatalError("'has' ACL argument missing");

    parseComponent(tok);

    if (ConfigParser::strtokFile())
        throw Cfg::FatalError("multiple components not supported for 'has' ACL");
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
    else
        throw Cfg::FatalError(ToSBuf("unsupported component '", token, "' for 'has' ACL"));
}

