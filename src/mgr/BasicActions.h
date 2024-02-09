/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_BASICACTIONS_H
#define SQUID_SRC_MGR_BASICACTIONS_H

#include "mgr/Action.h"

/* a collection of simple, mostly stateless actions */

namespace Mgr
{

/// A dummy action placeholder for the no-action requests
/// a templated Cache Manager index ('home') page.
/// Display output is produced directly by the receiving worker
/// without invoking the co-ordinator or action Job.
class IndexAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void dump(StoreEntry *entry) override;

protected:
    IndexAction(const CommandPointer &cmd);
};

/// returns available Cache Manager actions and their access requirements
class MenuAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void dump(StoreEntry *entry) override;

protected:
    MenuAction(const CommandPointer &cmd);
};

/// shuts Squid down
class ShutdownAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void dump(StoreEntry *entry) override;

protected:
    ShutdownAction(const CommandPointer &cmd);
};

/// reconfigures Squid
class ReconfigureAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void dump(StoreEntry *entry) override;

protected:
    ReconfigureAction(const CommandPointer &cmd);
};

/// starts log rotation
class RotateAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void dump(StoreEntry *entry) override;

protected:
    RotateAction(const CommandPointer &cmd);
};

/// changes offline mode
class OfflineToggleAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void dump(StoreEntry *entry) override;

protected:
    OfflineToggleAction(const CommandPointer &cmd);
};

/// Registers profiles for the actions above; TODO: move elsewhere?
void RegisterBasics();

} // namespace Mgr

#endif /* SQUID_SRC_MGR_BASICACTIONS_H */

