/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_IO_ACTION_H
#define SQUID_MGR_IO_ACTION_H

#include "mgr/Action.h"
#include "structs.h" /* _iostats::histSize */

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
    double http_read_hist[_iostats::histSize];
    double ftp_read_hist[_iostats::histSize];
    double gopher_read_hist[_iostats::histSize];
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
