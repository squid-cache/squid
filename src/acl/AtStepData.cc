/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "acl/AtStepData.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "wordlist.h"

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
ACLAtStepData::match(Ssl::BumpStep  toFind)
{
    for (std::list<Ssl::BumpStep>::const_iterator it = values.begin(); it != values.end(); ++it) {
        if (*it == toFind)
            return true;
    }
    return false;
}

SBufList
ACLAtStepData::dump() const
{
    SBufList sl;
    for (std::list<Ssl::BumpStep>::const_iterator it = values.begin(); it != values.end(); ++it) {
        sl.push_back(SBuf(*it == Ssl::bumpStep1 ? "SslBump1" :
                          *it == Ssl::bumpStep2 ? "SslBump2" :
                          *it == Ssl::bumpStep3 ? "SslBump3" : "???"));
    }
    return sl;
}

void
ACLAtStepData::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        if (strcasecmp(t, "SslBump1") == 0) {
            values.push_back(Ssl::bumpStep1);
        } else if (strcasecmp(t, "SslBump2") == 0) {
            values.push_back(Ssl::bumpStep2);
        } else if (strcasecmp(t, "SslBump3") == 0) {
            values.push_back(Ssl::bumpStep3);
        } else {
            debugs(28, DBG_CRITICAL, "FATAL: invalid AtStep step: " << t);
            self_destruct();
        }
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

#endif /* USE_OPENSSL */

