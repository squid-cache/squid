/*
 * DEBUG: section 84    Helper process maintenance
 * AUTHOR: Harvest Derived?
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_HELPER_H
#define SQUID_HELPER_H

#include "base/AsyncCall.h"
#include "cbdata.h"
#include "comm/forward.h"
#include "dlink.h"
#include "ip/Address.h"
#include "HelperChildConfig.h"

class helper_request;

typedef void HLPSCB(void *, void *lastserver, char *buf);

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
    HelperChildConfig childs;    ///< Configuration settings for number running.
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
     */
    void closePipesSafely();

    /** Closes the reading pipe.
     * If the read and write sockets are the same the write pipe will
     * also be closed. Otherwise its left open for later handling.
     */
    void closeWritePipeSafely();

public:
    int index;
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
        unsigned int busy:1;
        unsigned int writing:1;
        unsigned int closing:1;
        unsigned int shutdown:1;
        unsigned int reserved:1;
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
    helper_request **requests;

private:
    CBDATA_CLASS2(helper_server);
};

class helper_stateful_request;

class helper_stateful_server : public HelperServerBase
{
public:
    /* MemBuf wqueue; */
    /* MemBuf writebuf; */

    statefulhelper *parent;
    helper_stateful_request *request;

    void *data;			/* State data used by the calling routines */

private:
    CBDATA_CLASS2(helper_stateful_server);
};

class helper_request
{

public:
    MEMPROXY_CLASS(helper_request);
    char *buf;
    HLPCB *callback;
    void *data;

    struct timeval dispatch_time;
};

MEMPROXY_CLASS_INLINE(helper_request);

class helper_stateful_request
{

public:
    MEMPROXY_CLASS(helper_stateful_request);
    char *buf;
    HLPSCB *callback;
    int placeholder;		/* if 1, this is a dummy request waiting for a stateful helper to become available */
    void *data;
};

MEMPROXY_CLASS_INLINE(helper_stateful_request);

/* helper.c */
void helperOpenServers(helper * hlp);
void helperStatefulOpenServers(statefulhelper * hlp);
void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver);
void helperStats(StoreEntry * sentry, helper * hlp, const char *label = NULL);
void helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp, const char *label = NULL);
void helperShutdown(helper * hlp);
void helperStatefulShutdown(statefulhelper * hlp);
void helperStatefulReleaseServer(helper_stateful_server * srv);
void *helperStatefulServerGetData(helper_stateful_server * srv);

#endif /* SQUID_HELPER_H */
