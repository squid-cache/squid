/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    debugs(16, 5, MYNAME);
}

Mgr::MenuAction::Pointer
Mgr::MenuAction::Create(const Command::Pointer &cmd)
{
    return new MenuAction(cmd);
}

Mgr::MenuAction::MenuAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, MYNAME);
}

/// A table summarizing available Cache Manager actions:
///   table-row = SP 1*VCHAR 1*( HTAB 0*VCHAR )
void
Mgr::MenuAction::report(std::ostream &os)
{
    const auto &menu = CacheManager::GetInstance()->menu();

    for (const auto &a : menu) {
        os << ' ' << a->name
           << '\t' << a->desc
           << '\t' << CacheManager::GetInstance()->ActionProtection(a)
           << '\n';
    }
}

Mgr::ShutdownAction::Pointer
Mgr::ShutdownAction::Create(const Command::Pointer &cmd)
{
    return new ShutdownAction(cmd);
}

Mgr::ShutdownAction::ShutdownAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, MYNAME);
}

void
Mgr::ShutdownAction::report(std::ostream &)
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
    debugs(16, 5, MYNAME);
}

void
Mgr::ReconfigureAction::report(std::ostream &os)
{
    debugs(16, DBG_IMPORTANT, "Reconfigure by Cache Manager command.");
    os << "Reconfiguring Squid Process ... \n";
    reconfigure(SIGHUP);
}

Mgr::RotateAction::Pointer
Mgr::RotateAction::Create(const Command::Pointer &cmd)
{
    return new RotateAction(cmd);
}

Mgr::RotateAction::RotateAction(const Command::Pointer &aCmd): Action(aCmd)
{
    debugs(16, 5, MYNAME);
}

void
Mgr::RotateAction::report(std::ostream &os)
{
    debugs(16, DBG_IMPORTANT, "Rotate Logs by Cache Manager command.");
    os << "Rotating Squid Process Logs ... \n";
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
    debugs(16, 5, MYNAME);
}

void
Mgr::OfflineToggleAction::report(std::ostream &os)
{
    Config.onoff.offline = !Config.onoff.offline;
    debugs(16, DBG_IMPORTANT, "offline_mode now " << (Config.onoff.offline ? "ON" : "OFF") << " by Cache Manager request.");

    os << "offline_mode is now " << (Config.onoff.offline ? "ON" : "OFF") << '\n';
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

