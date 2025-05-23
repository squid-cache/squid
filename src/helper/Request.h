/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HELPER_REQUEST_H
#define SQUID_SRC_HELPER_REQUEST_H

#include "cbdata.h"
#include "helper/forward.h"
#include "mem/AllocatorProxy.h"
#include "time/gadgets.h"

namespace Helper
{

class Request
{
    MEMPROXY_CLASS(Helper::Request);

public:
    Request(HLPCB *c, void *d, const char *b) :
        buf(b ? xstrdup(b) : nullptr),
        callback(c),
        data(cbdataReference(d)),
        placeholder(b == nullptr),
        Id(0),
        retries(0)
    {
        memset(&dispatch_time, 0, sizeof(dispatch_time));
    }

    ~Request() {
        cbdataReferenceDone(data);
        xfree(buf);
    }

    char *buf;
    HLPCB *callback;
    void *data;

    int placeholder;            /* if 1, this is a dummy request waiting for a stateful helper to become available */
    struct timeval dispatch_time;
    uint64_t Id;
    /**
     * A helper may configured to retry timed out requests or on BH replies.
     * We attempt to recover by trying the lookup again, but limit the
     * number of retries to prevent lag and lockups.
     * This tracks the number of previous failures for the request.
     */
    int retries;
    bool timedOut(time_t timeout) {return (squid_curtime - dispatch_time.tv_sec) > timeout;}
};

} // namespace Helper

#endif /* SQUID_SRC_HELPER_REQUEST_H */

