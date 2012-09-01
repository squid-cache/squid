/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_ACTION_CREATOR_H
#define SQUID_MGR_ACTION_CREATOR_H

#include "mgr/forward.h"

namespace Mgr
{

/** Creates objects of the right Action class, parameterized with Command.
 * A part of the Action profile that allows Cache Manager be ignorant about
 * specific Action classes (\see Mgr::ActionProfile).
 */
class ActionCreator: public RefCountable
{
public:
    typedef RefCount<ActionCreator> Pointer;

    virtual ~ActionCreator() {}

    /// returns a pointer to the new Action object for cmd; never nil
    virtual ActionPointer create(const CommandPointer &cmd) const = 0;
};

} // namespace Mgr

#endif /* SQUID_MGR_ACTION_CREATOR_H */
