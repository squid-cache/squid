/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATION__DYNAMIC_GROUP_CFG_H
#define SQUID_ADAPTATION__DYNAMIC_GROUP_CFG_H

#include "SquidString.h"

#include <vector>

namespace Adaptation
{

/// DynamicServiceGroup configuration to remember future dynamic chains
class DynamicGroupCfg
{
public:
    typedef std::vector<String> Store;
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

