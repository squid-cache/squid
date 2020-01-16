/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_ACTION_PROFILE_H
#define SQUID_MGR_ACTION_PROFILE_H

#include "mgr/ActionCreator.h"
#include "mgr/forward.h"

namespace Mgr
{

/// hard-coded Cache Manager action configuration, including Action creator
class ActionProfile: public RefCountable
{
public:
    typedef RefCount<ActionProfile> Pointer;

public:
    ActionProfile(const char* aName, const char* aDesc, bool aPwReq,
                  bool anAtomic, const ActionCreatorPointer &aCreator):
        name(aName), desc(aDesc), isPwReq(aPwReq), isAtomic(anAtomic),
        creator(aCreator) {
    }

public:
    const char *name; ///< action label to uniquely identify this action
    const char *desc; ///< action description to build an action menu list
    bool isPwReq; ///< whether password is required to perform the action
    bool isAtomic; ///< whether action dumps everything in one dump() call
    ActionCreatorPointer creator; ///< creates Action objects with this profile
};

} // namespace Mgr

inline std::ostream &
operator <<(std::ostream &os, const Mgr::ActionProfile &profile)
{
    return os << profile.name;
}

#endif /* SQUID_MGR_ACTION_PROFILE_H */

