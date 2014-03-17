#ifndef SQUID_ADAPTATION__DYNAMIC_GROUP_CFG_H
#define SQUID_ADAPTATION__DYNAMIC_GROUP_CFG_H

#include "base/Vector.h"
#include "SquidString.h"

namespace Adaptation
{

/// DynamicServiceGroup configuration to remember future dynamic chains
class DynamicGroupCfg
{
public:
    typedef Vector<String> Store;
    typedef String Id;

    Id id; ///< group id
    Store services; ///< services in the group

    bool empty() const { return services.empty(); } ///< no services added
    void add(const String &item); ///< updates group id and services
    void clear(); ///< makes the config empty
};

inline
std::ostream &operator <<(std::ostream &os, const DynamicGroupCfg &cfg)
{
    return os << cfg.id;
}

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__DYNAMIC_GROUP_CFG_H */

