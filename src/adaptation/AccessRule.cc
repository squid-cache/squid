#include "squid.h"
#include "structs.h"

#include "ConfigParser.h"
#include "ACL.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"


int Adaptation::AccessRule::LastId = 0;

Adaptation::AccessRule::AccessRule(): id(++LastId), acl(NULL)
{
}

Adaptation::AccessRule::~AccessRule()
{
    // XXX: leaking acls here?
}

void
Adaptation::AccessRule::parse(ConfigParser &parser)
{
    ConfigParser::ParseString(&groupId);
    aclParseAccessLine(parser, &acl);
}

void
Adaptation::AccessRule::finalize()
{
    if (!group()) {
        debugs(93,0, "ERROR: Unknown adaptation service or group name: '" <<
            groupId << "'"); // TODO: fail on failures
	}
}

Adaptation::ServiceGroup *
Adaptation::AccessRule::group()
{
    return FindGroup(groupId);
}


Adaptation::AccessRules &
Adaptation::AllRules()
{
    static AccessRules TheRules;
    return TheRules;
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
