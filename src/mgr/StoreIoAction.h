/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_STORE_IO_ACTION_H
#define SQUID_MGR_STORE_IO_ACTION_H

#include "mgr/Action.h"

namespace Mgr
{

/// Store IO interface data
class StoreIoActionData
{
public:
    StoreIoActionData();
    StoreIoActionData& operator += (const StoreIoActionData& stats);

public:
    double create_calls;
    double create_select_fail;
    double create_create_fail;
    double create_success;
};

/// implement aggregated 'store_io' action
class StoreIoAction: public Action
{
protected:
    StoreIoAction(const CommandPointer &cmd);

public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void add(const Action& action);
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual void unpack(const Ipc::TypedMsgHdr& msg);

protected:
    /* Action API */
    virtual void collect();
    virtual void dump(StoreEntry* entry);

private:
    StoreIoActionData data;
};

} // namespace Mgr

#endif /* SQUID_MGR_STORE_IO_ACTION_H */

