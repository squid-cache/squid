/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_IO_ACTION_H
#define SQUID_MGR_IO_ACTION_H

#include "IoStats.h"
#include "mgr/Action.h"

namespace Mgr
{

/// store size histograms of network read() from peer server
class IoActionData
{
public:
    IoActionData();
    IoActionData& operator += (const IoActionData& stats);

public:
    double http_reads;
    double ftp_reads;
    double gopher_reads;
    double http_read_hist[IoStats::histSize];
    double ftp_read_hist[IoStats::histSize];
    double gopher_read_hist[IoStats::histSize];
};

/// implement aggregated 'io' action
class IoAction: public Action
{
protected:
    IoAction(const CommandPointer &cmd);

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
    IoActionData data;
};

} // namespace Mgr

#endif /* SQUID_MGR_IO_ACTION_H */

