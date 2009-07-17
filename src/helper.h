
/*
 * $Id: helper.h,v 1.9.4.1 2008/02/25 23:08:51 amosjeffries Exp $
 *
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

class helper_request;

typedef struct _helper helper;

typedef struct _helper_stateful statefulhelper;

typedef struct _helper_server helper_server;

typedef struct _helper_stateful_server helper_stateful_server;

typedef struct _helper_flags helper_flags;

typedef struct _helper_stateful_flags helper_stateful_flags;

typedef stateful_helper_callback_t HLPSCB(void *, void *lastserver, char *buf);

struct _helper
{
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    int n_to_start;           ///< Configuration setting of how many helper children should be running
    int n_running;            ///< Total helper children objects currently existing
    int n_active;             ///< Count of helper children active (not shutting down)
    int ipc_type;
    unsigned int concurrency;
    time_t last_queue_warn;
    time_t last_restart;

    struct
    {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    }

    stats;
};

struct _helper_stateful
{
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    int n_to_start;           ///< Configuration setting of how many helper children should be running
    int n_running;            ///< Total helper children objects currently existing
    int n_active;             ///< Count of helper children active (not shutting down)
    int ipc_type;
    MemAllocator *datapool;
    HLPSAVAIL *IsAvailable;
    HLPSONEQ *OnEmptyQueue;
    time_t last_queue_warn;
    time_t last_restart;

    struct
    {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    }

    stats;
};

struct _helper_server
{
    int index;
    int pid;
    int rfd;
    int wfd;
    MemBuf *wqueue;
    MemBuf *writebuf;
    char *rbuf;
    size_t rbuf_sz;
    size_t roffset;

    struct timeval dispatch_time;

    struct timeval answer_time;

    dlink_node link;
    helper *parent;
    helper_request **requests;

    struct _helper_flags
    {

unsigned int writing:
        1;

unsigned int closing:
        1;

unsigned int shutdown:
        1;
    }

    flags;

    struct
    {
        int uses;
        unsigned int pending;
    }

    stats;
    void *hIpc;
};

class helper_stateful_request;

struct _helper_stateful_server
{
    int index;
    int pid;
    int rfd;
    int wfd;
    /* MemBuf wqueue; */
    /* MemBuf writebuf; */
    char *rbuf;
    size_t rbuf_sz;
    size_t roffset;

    struct timeval dispatch_time;

    struct timeval answer_time;

    dlink_node link;
    dlink_list queue;
    statefulhelper *parent;
    helper_stateful_request *request;

    struct _helper_stateful_flags
    {

unsigned int busy:
        1;

unsigned int closing:
        1;

unsigned int shutdown:
        1;
        stateful_helper_reserve_t reserved;
    }

    flags;

    struct
    {
        int uses;
        int submits;
        int releases;
        int deferbyfunc;
        int deferbycb;
    }

    stats;
    int deferred_requests;	/* current number of deferred requests */
    void *data;			/* State data used by the calling routines */
    void *hIpc;
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

MEMPROXY_CLASS_INLINE(helper_request)

class helper_stateful_request
{

public:
    MEMPROXY_CLASS(helper_stateful_request);
    char *buf;
    HLPSCB *callback;
    int placeholder;		/* if 1, this is a dummy request waiting for a stateful helper to become available for deferred requests.*/
    void *data;
};

MEMPROXY_CLASS_INLINE(helper_stateful_request)

/* helper.c */
SQUIDCEXTERN void helperOpenServers(helper * hlp);
SQUIDCEXTERN void helperStatefulOpenServers(statefulhelper * hlp);
SQUIDCEXTERN void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
SQUIDCEXTERN void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver);
SQUIDCEXTERN void helperStats(StoreEntry * sentry, helper * hlp, const char *label = NULL);
SQUIDCEXTERN void helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp, const char *label = NULL);
SQUIDCEXTERN void helperShutdown(helper * hlp);
SQUIDCEXTERN void helperStatefulShutdown(statefulhelper * hlp);
SQUIDCEXTERN helper *helperCreate(const char *);
SQUIDCEXTERN statefulhelper *helperStatefulCreate(const char *);
SQUIDCEXTERN void helperFree(helper *);
SQUIDCEXTERN void helperStatefulFree(statefulhelper *);
SQUIDCEXTERN void helperStatefulReset(helper_stateful_server * srv);
SQUIDCEXTERN void helperStatefulReleaseServer(helper_stateful_server * srv);
SQUIDCEXTERN void *helperStatefulServerGetData(helper_stateful_server * srv);
SQUIDCEXTERN helper_stateful_server *helperStatefulDefer(statefulhelper *);



#endif /* SQUID_HELPER_H */
