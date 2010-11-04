/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_BASIC_ACTIONS_H
#define SQUID_MGR_BASIC_ACTIONS_H

#include "mgr/Action.h"

/* a collection of simple, mostly stateless actions */


namespace Mgr
{

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
