/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#ifndef SQUID_HELPER_H
#define SQUID_HELPER_H

#include "base/AsyncCall.h"
#include "base/InstanceId.h"
#include "cbdata.h"
#include "comm/forward.h"
#include "dlink.h"
#include "helper/ChildConfig.h"
#include "helper/forward.h"
#include "ip/Address.h"

/**
 * Managers a set of individual helper processes with a common queue of requests.
 *
 * With respect to load, a helper goes through these states (roughly):
 *   idle:   no processes are working on requests (and no requests are queued);
 *   normal: some, but not all processes are working (and no requests are queued);
 *   busy:   all processes are working (and some requests are possibly queued);
 *   full:   all processes are working and at least 2*#processes requests are queued.
 *
 * A "busy" helper queues new requests and issues a WARNING every 10 minutes or so.
 * A "full" helper either drops new requests or keeps queuing them, depending on
 *   whether the caller can handle dropped requests (trySubmit vs helperSubmit APIs).
 * An attempt to use a "full" helper that has been "full" for 3+ minutes kills worker.
 *   Given enough load, all helpers except for external ACL will make such attempts.
 */
class helper
{
    CBDATA_CLASS(helper);

public:
    inline helper(const char *name) :
            cmdline(NULL),
            id_name(name),
            ipc_type(0),
            full_time(0),
            last_queue_warn(0),
            last_restart(0),
            eom('\n') {
        memset(&stats, 0, sizeof(stats));
    }
    ~helper();

    ///< whether at least one more request can be successfully submitted
    bool queueFull() const;

    ///< If not full, submit request. Otherwise, either kill Squid or return false.
    bool trySubmit(const char *buf, HLPCB * callback, void *data);

public:
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    Helper::ChildConfig childs;    ///< Configuration settings for number running.
    int ipc_type;
    Ip::Address addr;
    time_t full_time; ///< when a full helper became full (zero for non-full helpers)
    time_t last_queue_warn;
    time_t last_restart;
    char eom;   ///< The char which marks the end of (response) message, normally '\n'

    struct _stats {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    } stats;

protected:
    friend void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
    void prepSubmit();
    void submit(const char *buf, HLPCB * callback, void *data);
};

class statefulhelper : public helper
{
    CBDATA_CLASS(statefulhelper);

public:
    inline statefulhelper(const char *name) : helper(name), datapool(NULL), IsAvailable(NULL), OnEmptyQueue(NULL) {}
    inline ~statefulhelper() {}

public:
    MemAllocator *datapool;
    HLPSAVAIL *IsAvailable;
    HLPSONEQ *OnEmptyQueue;

private:
    friend void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPCB * callback, void *data, helper_stateful_server * lastserver);
    void submit(const char *buf, HLPCB * callback, void *data, helper_stateful_server *lastserver);
};

/**
 * Fields shared between stateless and stateful helper servers.
 */
class HelperServerBase
{
public:
    /** Closes pipes to the helper safely.
     * Handles the case where the read and write pipes are the same FD.
     *
     * \param name displayed for the helper being shutdown if logging an error
     */
    void closePipesSafely(const char *name);

    /** Closes the reading pipe.
     * If the read and write sockets are the same the write pipe will
     * also be closed. Otherwise its left open for later handling.
     *
     * \param name displayed for the helper being shutdown if logging an error
     */
    void closeWritePipeSafely(const char *name);

public:
    /// Helper program identifier; does not change when contents do,
    ///   including during assignment
    const InstanceId<HelperServerBase> index;
    int pid;
    Ip::Address addr;
    Comm::ConnectionPointer readPipe;
    Comm::ConnectionPointer writePipe;
    void *hIpc;

    char *rbuf;
    size_t rbuf_sz;
    size_t roffset;

    struct timeval dispatch_time;
    struct timeval answer_time;

    dlink_node link;

    struct _helper_flags {
        bool writing;
        bool closing;
        bool shutdown;
        bool reserved;
    } flags;

    struct {
        uint64_t uses;     //< requests sent to this helper
        uint64_t replies;  //< replies received from this helper
        uint64_t pending;  //< queued lookups waiting to be sent to this helper
        uint64_t releases; //< times release() has been called on this helper (if stateful)
    } stats;
    void initStats();
};

class MemBuf;

class helper_server : public HelperServerBase
{
    CBDATA_CLASS(helper_server);

public:
    MemBuf *wqueue;
    MemBuf *writebuf;

    helper *parent;
    Helper::Request **requests;
};

class helper_stateful_server : public HelperServerBase
{
    CBDATA_CLASS(helper_stateful_server);

public:
    /* MemBuf wqueue; */
    /* MemBuf writebuf; */

    statefulhelper *parent;
    Helper::Request *request;

    void *data;			/* State data used by the calling routines */
};

/* helper.c */
void helperOpenServers(helper * hlp);
void helperStatefulOpenServers(statefulhelper * hlp);
void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPCB * callback, void *data, helper_stateful_server * lastserver);
void helperStats(StoreEntry * sentry, helper * hlp, const char *label = NULL);
void helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp, const char *label = NULL);
void helperShutdown(helper * hlp);
void helperStatefulShutdown(statefulhelper * hlp);
void helperStatefulReleaseServer(helper_stateful_server * srv);
void *helperStatefulServerGetData(helper_stateful_server * srv);

#endif /* SQUID_HELPER_H */
