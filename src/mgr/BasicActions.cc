/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "mgr/ActionCreator.h"
#include "mgr/ActionProfile.h"
#include "mgr/BasicActions.h"
#include "mgr/Registration.h"
#include "protos.h"
#include "SquidConfig.h"
#include "Store.h"

Mgr::IndexAction::Pointer
Mgr::IndexAction::Create(const Command::Pointer &cmd)
{
    return new IndexAction(cmd);
}

Mgr::IndexAction::IndexAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, HERE);
}

void
Mgr::IndexAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
}

Mgr::MenuAction::Pointer
Mgr::MenuAction::Create(const Command::Pointer &cmd)
{
    return new MenuAction(cmd);
}

Mgr::MenuAction::MenuAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, HERE);
}

void
Mgr::MenuAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);

    typedef CacheManager::Menu::const_iterator Iterator;
    const CacheManager::Menu& menu = CacheManager::GetInstance()->menu();

    for (Iterator a = menu.begin(); a != menu.end(); ++a) {
        storeAppendPrintf(entry, " %-22s\t%-32s\t%s\n",
                          (*a)->name, (*a)->desc,
                          CacheManager::GetInstance()->ActionProtection(*a));
    }
}

Mgr::ShutdownAction::Pointer
Mgr::ShutdownAction::Create(const Command::Pointer &cmd)
{
    return new ShutdownAction(cmd);
}

Mgr::ShutdownAction::ShutdownAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, HERE);
}

void
Mgr::ShutdownAction::dump(StoreEntry* entry)
{
    debugs(16, DBG_CRITICAL, "Shutdown by Cache Manager command.");
    shut_down(SIGTERM);
}

Mgr::ReconfigureAction::Pointer
Mgr::ReconfigureAction::Create(const Command::Pointer &cmd)
{
    return new ReconfigureAction(cmd);
}

Mgr::ReconfigureAction::ReconfigureAction(const Command::Pointer &aCmd):
    Action(aCmd)
{
    debugs(16, 5, HERE);
}

void
Mgr::ReconfigureAction::dump(StoreEntry* entry)
{
    debugs(16, DBG_IMPORTANT, "Reconfigure by Cache Manager command.");
    storeAppendPrintf(entry, "Reconfiguring Squid Process ....");
    reconfigure(SIGHUP);
}

Mgr::RotateAction::Pointer
Mgr::RotateAction::Create(const Command::Pointer &cmd)
{
    return new RotateAction(cmd);
}

Mgr::RotateAction::RotateAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, HERE);
}

void
Mgr::RotateAction::dump(StoreEntry* entry)
{
    debugs(16, DBG_IMPORTANT, "Rotate Logs by Cache Manager command.");
    storeAppendPrintf(entry, "Rotating Squid Process Logs ....");
#if defined(_SQUID_LINUX_THREADS_)
    rotate_logs(SIGQUIT);
#else
    rotate_logs(SIGUSR1);
#endif
}

Mgr::OfflineToggleAction::Pointer
Mgr::OfflineToggleAction::Create(const Command::Pointer &cmd)
{
    return new OfflineToggleAction(cmd);
}

Mgr::OfflineToggleAction::OfflineToggleAction(const Command::Pointer &aCmd):
    Action(aCmd)
{
    debugs(16, 5, HERE);
}

void
Mgr::OfflineToggleAction::dump(StoreEntry* entry)
{
    Config.onoff.offline = !Config.onoff.offline;
    debugs(16, DBG_IMPORTANT, "offline_mode now " << (Config.onoff.offline ? "ON" : "OFF") << " by Cache Manager request.");

    storeAppendPrintf(entry, "offline_mode is now %s\n",
                      Config.onoff.offline ? "ON" : "OFF");
}

void
Mgr::RegisterBasics()
{
    RegisterAction("index", "Cache Manager Interface", &Mgr::IndexAction::Create, 0, 1);
    RegisterAction("menu", "Cache Manager Menu", &Mgr::MenuAction::Create, 0, 1);
    RegisterAction("offline_toggle", "Toggle offline_mode setting", &Mgr::OfflineToggleAction::Create, 1, 1);
    RegisterAction("shutdown", "Shut Down the Squid Process", &Mgr::ShutdownAction::Create, 1, 1);
    RegisterAction("reconfigure", "Reconfigure Squid", &Mgr::ReconfigureAction::Create, 1, 1);
    RegisterAction("rotate", "Rotate Squid Logs", &Mgr::RotateAction::Create, 1, 1);
}

