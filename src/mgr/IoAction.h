/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_IO_ACTION_H
#define SQUID_MGR_IO_ACTION_H

#include "mgr/Action.h"
#include "IoStats.h"

namespace Mgr
{

/// store server-side network read() size histograms
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
