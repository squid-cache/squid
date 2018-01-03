/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_BASIC_ACTIONS_H
#define SQUID_MGR_BASIC_ACTIONS_H

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
    virtual void dump(StoreEntry *entry);

protected:
    IndexAction(const CommandPointer &cmd);
};

/// returns available Cache Manager actions and their access requirements
class MenuAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void dump(StoreEntry *entry);

protected:
    MenuAction(const CommandPointer &cmd);
};

/// shuts Squid down
class ShutdownAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void dump(StoreEntry *entry);

protected:
    ShutdownAction(const CommandPointer &cmd);
};

/// reconfigures Squid
class ReconfigureAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void dump(StoreEntry *entry);

protected:
    ReconfigureAction(const CommandPointer &cmd);
};

/// starts log rotation
class RotateAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void dump(StoreEntry *entry);

protected:
    RotateAction(const CommandPointer &cmd);
};

/// changes offline mode
class OfflineToggleAction: public Action
{
public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void dump(StoreEntry *entry);

protected:
    OfflineToggleAction(const CommandPointer &cmd);
};

/// Registeres profiles for the actions above; \todo move elsewhere?
void RegisterBasics();

} // namespace Mgr

#endif /* SQUID_MGR_BASIC_ACTIONS_H */

