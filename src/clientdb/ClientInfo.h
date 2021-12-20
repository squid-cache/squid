/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_CLIENTINFO_H
#define SQUID__SRC_CLIENTINFO_H

#include "base/ByteCounter.h"
#include "base/RefCount.h"
#include "enums.h"
#include "ip/Address.h"
#include "LogTags.h"
#include "mem/forward.h"
#include "typedefs.h"

#if USE_DELAY_POOLS
#include "BandwidthBucket.h"
#include "cbdata.h"
#endif

#include <deque>

#if USE_DELAY_POOLS
class CommQuotaQueue;
#endif

class ClientInfo : public RefCountable
#if USE_DELAY_POOLS
    , public BandwidthBucket
#endif
{
    MEMPROXY_CLASS(ClientInfo);

public:
    typedef RefCount<ClientInfo> Pointer;

    explicit ClientInfo(const Ip::Address &);
    ~ClientInfo();

    Ip::Address addr;

    struct Protocol {
        Protocol() {
            memset(result_hist, 0, sizeof(result_hist));
        }

        int result_hist[LOG_TYPE_MAX];
        int n_requests = 0;
        ByteCounter kbytes_in;
        ByteCounter kbytes_out;
        ByteCounter hit_kbytes_out;
    } Http, Icp;

    struct Cutoff {
        time_t time = 0;
        int n_req = 0;
        int n_denied = 0;
    } cutoff;
    int n_established = 0; ///< number of current established connections
    time_t last_seen = 0;
#if USE_DELAY_POOLS
    bool writeLimitingActive = false; ///< Is write limiter active
    bool firstTimeConnection = true;///< is this first time connection for this client

    CommQuotaQueue *quotaQueue = nullptr; ///< clients waiting for more write quota
    int rationedQuota = 0; ///< precomputed quota preserving fairness among clients
    int rationedCount = 0; ///< number of clients that will receive rationedQuota
    bool eventWaiting = false; ///< waiting for commHandleWriteHelper event to fire

    // all those functions access Comm fd_table and are defined in comm.cc
    bool hasQueue() const;  ///< whether any clients are waiting for write quota
    bool hasQueue(const CommQuotaQueue*) const;  ///< has a given queue
    unsigned int quotaEnqueue(int fd); ///< client starts waiting in queue; create the queue if necessary
    int quotaPeekFd() const; ///< returns the next fd reservation
    unsigned int quotaPeekReserv() const; ///< returns the next reserv. to pop
    void quotaDequeue(); ///< pops queue head from queue
    void kickQuotaQueue(); ///< schedule commHandleWriteHelper call
    /// either selects the head descriptor for writing or calls quotaDequeue()
    void writeOrDequeue();

    /* BandwidthBucket API */
    virtual int quota() override; ///< allocate quota for a just dequeued client
    virtual bool applyQuota(int &nleft, Comm::IoCallback *state) override;
    virtual void scheduleWrite(Comm::IoCallback *state) override;
    virtual void onFdClosed() override;
    virtual void reduceBucket(int len) override;

    void quotaDumpQueue(); ///< dumps quota queue for debugging

    /**
     * Configure client write limiting (note:"client" here means - IP). It is called
     * by httpAccept in client_side.cc, where the initial bucket size (anInitialBurst)
     * computed, using the configured maximum bucket value and configured initial
     * bucket value(50% by default).
     *
     * \param  writeSpeedLimit is speed limit configured in config for this pool
     * \param  initialBurst is initial bucket size to use for this client(i.e. client can burst at first)
     *  \param highWatermark is maximum bucket value
     */
    void setWriteLimiter(const int aWriteSpeedLimit, const double anInitialBurst, const double aHighWatermark);
#endif /* USE_DELAY_POOLS */
};

#if USE_DELAY_POOLS
// a queue of Comm clients waiting for I/O quota controlled by delay pools
class CommQuotaQueue
{
    CBDATA_CLASS(CommQuotaQueue);

public:
    CommQuotaQueue(ClientInfo *info);
    ~CommQuotaQueue();

    bool empty() const { return fds.empty(); }
    size_t size() const { return fds.size(); }
    int front() const { return fds.front(); }
    unsigned int enqueue(int fd);
    void dequeue();

    ClientInfo *clientInfo; ///< bucket responsible for quota maintenance

    // these counters might overflow; that is OK because they are for IDs only
    int ins; ///< number of enqueue calls, used to generate a "reservation" ID
    int outs; ///< number of dequeue calls, used to check the "reservation" ID

private:
    // TODO: optimize using a Ring- or List-based store?
    typedef std::deque<int> Store;
    Store fds; ///< descriptor queue
};
#endif /* USE_DELAY_POOLS */

#endif

