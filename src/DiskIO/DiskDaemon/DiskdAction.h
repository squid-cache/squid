/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side DISKD I/O functions. */

#ifndef SQUID_SRC_DISKIO_DISKDAEMON_DISKDACTION_H
#define SQUID_SRC_DISKIO_DISKDAEMON_DISKDACTION_H

#include "ipc/forward.h"
#include "mgr/Action.h"
#include "mgr/forward.h"

/// store disk daemon stats
class DiskdActionData
{
public:
    DiskdActionData();
    DiskdActionData& operator += (const DiskdActionData& stats);

public:
    double sent_count;
    double recv_count;
    double max_away;
    double max_shmuse;
    double open_fail_queue_len;
    double block_queue_len;
    double open_ops;
    double open_success;
    double open_fail;
    double create_ops;
    double create_success;
    double create_fail;
    double close_ops;
    double close_success;
    double close_fail;
    double unlink_ops;
    double unlink_success;
    double unlink_fail;
    double read_ops;
    double read_success;
    double read_fail;
    double write_ops;
    double write_success;
    double write_fail;
};

/// implement aggregated 'diskd' action
class DiskdAction: public Mgr::Action
{
protected:
    DiskdAction(const Mgr::CommandPointer &aCmd);

public:
    static Pointer Create(const Mgr::CommandPointer &aCmd);
    /* Action API */
    void add(const Mgr::Action& action) override;
    void pack(Ipc::TypedMsgHdr& hdrMsg) const override;
    void unpack(const Ipc::TypedMsgHdr& hdrMsg) override;

protected:
    /* Action API */
    void collect() override;
    void dump(StoreEntry* entry) override;

private:
    DiskdActionData data;
};

#endif /* SQUID_SRC_DISKIO_DISKDAEMON_DISKDACTION_H */

