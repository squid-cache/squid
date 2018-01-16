/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_FUN_ACTION_H
#define SQUID_MGR_FUN_ACTION_H

#include "mgr/Action.h"
#include "mgr/ActionCreator.h"

namespace Mgr
{

/// function-based cache manager Action; a wrapper for so called legacy actions
/// that do everything using a single OBJH function
class FunAction: public Action
{
protected:
    FunAction(const CommandPointer &cmd, OBJH *aHandler);

public:
    static Pointer Create(const CommandPointer &cmd, OBJH *aHandler);

    /* Action API */
    virtual void respond(const Request& request);
    // we cannot aggregate because we do not even know what the handler does
    virtual bool aggregatable() const { return false; }

protected:
    /* Action API */
    virtual void dump(StoreEntry *entry);

private:
    OBJH *handler; ///< legacy function that collects and dumps info
};

/// creates FunAction using ActionCreator API
class FunActionCreator: public ActionCreator
{
public:
    explicit FunActionCreator(OBJH *aHandler): handler(aHandler) {}

    /* ActionCreator API */
    virtual Action::Pointer create(const CommandPointer &cmd) const {
        return FunAction::Create(cmd, handler);
    }

private:
    OBJH *handler; ///< legacy function to pass to the FunAction wrapper
};

} // namespace Mgr

#endif /* SQUID_MGR_FUN_ACTION_H */

