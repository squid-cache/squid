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

#include "squid.h"
#include "cbdata.h"
#include "ip/Address.h"
#include "HelperChildConfig.h"

class helper_request;

typedef struct _helper_flags helper_flags;

typedef struct _helper_stateful_flags helper_stateful_flags;

typedef void HLPSCB(void *, void *lastserver, char *buf);

class helper
{
public:
    inline helper(const char *name) : cmdline(NULL), id_name(name) {};
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

    struct _stats {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    } stats;
    /// True if callback expects the whole helper output, as a c-string.
    bool return_full_reply;

private:
    CBDATA_CLASS2(helper);
};

class statefulhelper : public helper
{
public:
    inline statefulhelper(const char *name) : helper(name) {};
    inline ~statefulhelper() {};

public:
    MemAllocator *datapool;
    HLPSAVAIL *IsAvailable;
    HLPSONEQ *OnEmptyQueue;

private:
    CBDATA_CLASS2(statefulhelper);
};

/*
 * Fields shared between stateless and stateful helper servers.
 */
class HelperServerBase
{
public:
    int index;
    int pid;
    Ip::Address addr;
    int rfd;
    int wfd;
    void *hIpc;

    char *rbuf;
    size_t rbuf_sz;
    size_t roffset;

    struct timeval dispatch_time;
    struct timeval answer_time;

    dlink_node link;
};

class helper_server : public HelperServerBase
{
public:
    MemBuf *wqueue;
    MemBuf *writebuf;

    helper *parent;
    helper_request **requests;

    struct _helper_flags {
        unsigned int writing:1;
        unsigned int closing:1;
        unsigned int shutdown:1;
    } flags;

    struct {
        int uses;
        unsigned int pending;
    } stats;
};

class helper_stateful_request;

class helper_stateful_server : public HelperServerBase
{
public:
    /* MemBuf wqueue; */
    /* MemBuf writebuf; */

    statefulhelper *parent;
    helper_stateful_request *request;

    struct _helper_stateful_flags {
        unsigned int busy:1;
        unsigned int closing:1;
        unsigned int shutdown:1;
        unsigned int reserved:1;
    } flags;

    struct {
        int uses;
        int submits;
        int releases;
    } stats;
    void *data;			/* State data used by the calling routines */
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
SQUIDCEXTERN void helperOpenServers(helper * hlp);
SQUIDCEXTERN void helperStatefulOpenServers(statefulhelper * hlp);
SQUIDCEXTERN void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
SQUIDCEXTERN void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver);
SQUIDCEXTERN void helperStats(StoreEntry * sentry, helper * hlp, const char *label = NULL);
SQUIDCEXTERN void helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp, const char *label = NULL);
SQUIDCEXTERN void helperShutdown(helper * hlp);
SQUIDCEXTERN void helperStatefulShutdown(statefulhelper * hlp);
SQUIDCEXTERN void helperStatefulReleaseServer(helper_stateful_server * srv);
SQUIDCEXTERN void *helperStatefulServerGetData(helper_stateful_server * srv);


#endif /* SQUID_HELPER_H */
