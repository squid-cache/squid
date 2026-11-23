/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_COMM_IDLECONNLIST_H
#define SQUID_SRC_COMM_IDLECONNLIST_H

#include "base/CbcPointer.h"
#include "base/RunnersRegistry.h"
#include "comm/forward.h"
#include "CommCalls.h"
#include "hash.h"

class PconnPool;

namespace Comm
{

#define PCONN_HIST_SZ (1<<16)

/**
 * A list of connections currently open to a particular destination end-point.
 */
class IdleConnList: public hash_link, private IndependentRunner
{
    CBDATA_CLASS(IdleConnList);

public:
    IdleConnList(const char *key, PconnPool *parent);
    ~IdleConnList() override;

    /// Pass control of the connection to the idle list.
    void push(const Comm::ConnectionPointer &);

    /// get first conn which is not pending read fd.
    Comm::ConnectionPointer pop();

    /** Search the list for a connection which matches the 'key' details
     * and pop it off the list.
     * The list is created based on remote IP:port hash. This further filters
     * the choices based on specific local-end details requested.
     * If nothing usable is found the a nil pointer is returned.
     */
    Comm::ConnectionPointer findUseable(const Comm::ConnectionPointer &key);

    void clearHandlers(const Comm::ConnectionPointer &);

    // TODO: Upgrade to return size_t
    int count() const { return size_; }

    void closeN(size_t count);

    /* IndependentRunner API */
    void endingShutdown() override;

private:
    bool isAvailable(int i) const;
    bool removeAt(size_t index);
    int findIndexOf(const Comm::ConnectionPointer &) const;
    void findAndClose(const Comm::ConnectionPointer &);
    static IOCB Read;
    static CTCB Timeout;

private:
    /** List of connections we are holding.
     * Sorted as FIFO list for most efficient speeds on pop() and findUsable()
     * The worst-case pop() and scans occur on timeout and link closure events
     * where timing is less critical. Occasional slow additions are okay.
     */
    Comm::ConnectionPointer *theList_;

    /// Number of entries theList can currently hold without re-allocating (capacity).
    size_t capacity_;
    ///< Number of in-use entries in theList
    size_t size_;

    /** The pool containing this sub-list.
     * The parent performs all stats accounting, and
     * will delete us when it dies. It persists for the
     * full duration of our existence.
     */
    PconnPool *parent_;

    char fakeReadBuf_[4096]; // TODO: kill magic number.
};

} // namespace Comm

#endif /* SQUID_SRC_COMM_IDLECONNLIST_H */
