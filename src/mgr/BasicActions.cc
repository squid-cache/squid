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
#include "mgr/ReportStream.h"
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

void
Mgr::MenuAction::dump(StoreEntry *e)
{
    // TODO get Accept header from e->mem()->request to decide here and contentType()?

    ReportStreamPointer os;
    if (strncasecmp(contentType(), "text/yaml", 9) == 0) {
        os = new Mgr::ReportYaml(*e);
    } else {
        os = new Mgr::ReportPlain(*e);
    }
    *os << MgrReportStart;
    report(*os);
    *os << MgrReportEnd;
}

/// A table summarizing available Cache Manager actions:
///   table-row = SP 1*VCHAR 1*( HTAB 0*VCHAR )
void
Mgr::MenuAction::report(Mgr::ReportStream &os)
{
    const auto &menu = CacheManager::GetInstance()->menu();

    const auto savedFlags = os.flags();
    const auto savedFill = os.fill();

    os << "Cache Manager menu:" << std::endl;
    os << MgrTableStart;
    for (const auto &a : menu) {
        os << MgrTableRowStart
           << MgrTableCellStart << std::setw(22) << a->name << std::setw(0) << MgrTableCellEnd
           << MgrTableCellStart << std::setw(32) << a->desc << std::setw(0) << MgrTableCellEnd
           << MgrTableCellStart << CacheManager::GetInstance()->ActionProtection(a) << MgrTableCellEnd
           << MgrTableRowEnd;
    }
    os << MgrTableEnd;

    os.fill(savedFill);
    os.flags(savedFlags);
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
Mgr::ShutdownAction::report(ReportStream &)
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
Mgr::ReconfigureAction::report(ReportStream &os)
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
Mgr::RotateAction::report(ReportStream &os)
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
Mgr::OfflineToggleAction::report(ReportStream &os)
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

