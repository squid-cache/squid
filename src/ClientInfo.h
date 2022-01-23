/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_CLIENTINFO_H
#define SQUID__SRC_CLIENTINFO_H

#if USE_DELAY_POOLS
#include "BandwidthBucket.h"
#endif
#include "base/ByteCounter.h"
#include "cbdata.h"
#include "enums.h"
#include "hash.h"
#include "ip/Address.h"
#include "LogTags.h"
#include "mem/forward.h"
#include "typedefs.h"

#include <deque>

#if USE_DELAY_POOLS
class CommQuotaQueue;
#endif

class ClientInfo : public hash_link
#if USE_DELAY_POOLS
    , public BandwidthBucket
#endif
{
    MEMPROXY_CLASS(ClientInfo);

public:
    explicit ClientInfo(const Ip::Address &);
    ~ClientInfo();

    Ip::Address addr;

    struct Protocol {
        Protocol() : n_requests(0) {
            memset(result_hist, 0, sizeof(result_hist));
        }

        int result_hist[LOG_TYPE_MAX];
        int n_requests;
        ByteCounter kbytes_in;
        ByteCounter kbytes_out;
        ByteCounter hit_kbytes_out;
    } Http, Icp;

    struct Cutoff {
        Cutoff() : time(0), n_req(0), n_denied(0) {}

        time_t time;
        int n_req;
        int n_denied;
    } cutoff;
    int n_established;          /* number of current established connections */
    time_t last_seen;
#if USE_DELAY_POOLS
    bool writeLimitingActive; ///< Is write limiter active
    bool firstTimeConnection;///< is this first time connection for this client

    CommQuotaQueue *quotaQueue; ///< clients waiting for more write quota
    int rationedQuota; ///< precomputed quota preserving fairness among clients
    int rationedCount; ///< number of clients that will receive rationedQuota
    bool eventWaiting; ///< waiting for commHandleWriteHelper event to fire

    // all those functions access Comm fd_table and are defined in comm.cc
    bool hasQueue() const;  ///< whether any clients are waiting for write quota
    bool hasQueue(const CommQuotaQueue*) const;  ///< has a given queue
    unsigned int quotaEnqueue(int fd); ///< client starts waiting in queue; create the queue if necessary
    int quotaPeekFd() const; ///< retuns the next fd reservation
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
     * computed, using the configured maximum bucket vavlue and configured initial
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

