/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

class helper
{
public:
    inline helper(const char *name) :
        cmdline(NULL),
        id_name(name),
        ipc_type(0),
        last_queue_warn(0),
        last_restart(0),
        eom('\n') {
        memset(&stats, 0, sizeof(stats));
    }
    ~helper();

public:
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    Helper::ChildConfig childs;    ///< Configuration settings for number running.
    int ipc_type;
    Ip::Address addr;
    time_t last_queue_warn;
    time_t last_restart;
    char eom;   ///< The char which marks the end of (response) message, normally '\n'

    struct _stats {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    } stats;

private:
    CBDATA_CLASS2(helper);
};

class statefulhelper : public helper
{
public:
    inline statefulhelper(const char *name) : helper(name), datapool(NULL), IsAvailable(NULL), OnEmptyQueue(NULL) {};
    inline ~statefulhelper() {};

public:
    MemAllocator *datapool;
    HLPSAVAIL *IsAvailable;
    HLPSONEQ *OnEmptyQueue;

private:
    CBDATA_CLASS2(statefulhelper);
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
public:
    MemBuf *wqueue;
    MemBuf *writebuf;

    helper *parent;
    Helper::Request **requests;

private:
    CBDATA_CLASS2(helper_server);
};

class helper_stateful_server : public HelperServerBase
{
public:
    /* MemBuf wqueue; */
    /* MemBuf writebuf; */

    statefulhelper *parent;
    Helper::Request *request;

    void *data;         /* State data used by the calling routines */

private:
    CBDATA_CLASS2(helper_stateful_server);
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

