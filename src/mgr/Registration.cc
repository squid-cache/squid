/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "CacheManager.h"
#include "mgr/FunAction.h"
#include "mgr/Registration.h"

namespace Mgr {

/// creates FunAction using ActionCreator API
class FunActionCreator: public ActionCreator
{
public:
    explicit FunActionCreator(OBJH *aHandler): handler(aHandler) {}

    /* ActionCreator API */
    Action::Pointer create(const CommandPointer &cmd) const override {
        return FunAction::Create(cmd, handler);
    }

private:
    OBJH *handler; ///< legacy function to pass to the FunAction wrapper
};

/// creates Action using supplied Action::Create method and command
class ClassActionCreator: public ActionCreator
{
public:
    using Handler = ClassActionCreationHandler;

public:
    ClassActionCreator(Handler *aHandler): handler(aHandler) {}

    /* ActionCreator API */
    Action::Pointer create(const Command::Pointer &cmd) const override {
        return handler(cmd);
    }

private:
    Handler *handler; ///< configured Action object creator
};

} // namespace Mgr

void
Mgr::RegisterAction(char const * action, char const * desc,
                    OBJH * handler,
                    const Protected protection,
                    const Atomic atomicity,
                    const Format format)
{
    debugs(16, 3, "function-based " << action);
    const auto profile = ActionProfile::Pointer::Make(action,
                         desc, new FunActionCreator(handler),
                         protection, atomicity, format);
    CacheManager::GetInstance()->registerProfile(profile);
}

void
Mgr::RegisterAction(char const * action, char const * desc,
                    ClassActionCreationHandler *handler,
                    const Protected protection,
                    const Atomic atomicity,
                    const Format format)
{
    debugs(16, 3, "class-based " << action);
    const auto profile = ActionProfile::Pointer::Make(action,
                         desc, new ClassActionCreator(handler),
                         protection, atomicity, format);
    CacheManager::GetInstance()->registerProfile(profile);
}

