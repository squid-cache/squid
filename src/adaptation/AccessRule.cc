/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "ConfigParser.h"
#include "Debug.h"

int Adaptation::AccessRule::LastId = 0;

Adaptation::AccessRule::AccessRule(const String &aGroupId): id(++LastId), groupId(aGroupId), acl(NULL)
{
}

Adaptation::AccessRule::~AccessRule()
{
    delete acl;
}

void
Adaptation::AccessRule::parse(ConfigParser &parser)
{
    aclParseAccessLine("adaptation_access", parser, &acl);
}

void
Adaptation::AccessRule::finalize()
{
    if (!group()) { // no explicit group
        debugs(93,7, HERE << "no service group: " << groupId);
        // try to add a one-service group
        if (FindService(groupId) != NULL) {
            ServiceGroupPointer g = new SingleService(groupId);
            g->finalize(); // explicit groups were finalized before rules
            AllGroups().push_back(g);
        }
    }

    if (!group()) {
        debugs(93, DBG_CRITICAL, "ERROR: Unknown adaptation service or group name: '" <<
               groupId << "'"); // TODO: fail on failures
    }
}

Adaptation::ServiceGroupPointer
Adaptation::AccessRule::group()
{
    return FindGroup(groupId);
}

Adaptation::AccessRules &
Adaptation::AllRules()
{
    static AccessRules *TheRules = new AccessRules;
    return *TheRules;
}

// TODO: make AccessRules::find work
Adaptation::AccessRule *
Adaptation::FindRule(const AccessRule::Id &id)
{
    typedef AccessRules::iterator ARI;
    for (ARI i = AllRules().begin(); i != AllRules().end(); ++i) {
        if ((*i)->id == id)
            return *i;
    }

    return NULL;
}

Adaptation::AccessRule *
Adaptation::FindRuleByGroupId(const String &groupId)
{
    typedef AccessRules::iterator ARI;
    for (ARI i = AllRules().begin(); i != AllRules().end(); ++i) {
        if ((*i)->groupId == groupId)
            return *i;
    }

    return NULL;
}

