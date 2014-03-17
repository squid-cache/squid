#ifndef SQUID_ADAPTATION__ACCESS_RULE_H
#define SQUID_ADAPTATION__ACCESS_RULE_H

#include "acl/forward.h"
#include "adaptation/forward.h"
#include "SquidString.h"

class ConfigParser;

namespace Adaptation
{

// manages adaptation_access configuration by associating an acl with
// an adaptation service group
class AccessRule
{
public:
    AccessRule(const String &groupId);
    ~AccessRule();

    void parse(ConfigParser &parser);
    void finalize();

    // service group consisting of one or more services
    ServiceGroupPointer group();

public:
    typedef int Id;
    const Id id;
    String groupId;
    acl_access *acl;

private:
    static Id LastId;
};

typedef Vector<Adaptation::AccessRule*> AccessRules;
AccessRules &AllRules();
AccessRule *FindRule(const AccessRule::Id &id);
AccessRule *FindRuleByGroupId(const String &groupId);

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__ACCESS_RULE_H */
