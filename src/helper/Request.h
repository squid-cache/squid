/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HELPER_REQUEST_H
#define _SQUID_SRC_HELPER_REQUEST_H

#include "helper/forward.h"

namespace Helper
{

class Request
{
public:
    Request(HLPCB *c, void *d, const char *b) :
        buf(b ? xstrdup(b) : NULL),
        callback(c),
        data(cbdataReference(d)),
        placeholder(b == NULL)
    {
        memset(&dispatch_time, 0, sizeof(dispatch_time));
    }

    ~Request() {
        cbdataReferenceDone(data);
        xfree(buf);
    }

    MEMPROXY_CLASS(Helper::Request);
    char *buf;
    HLPCB *callback;
    void *data;

    int placeholder;            /* if 1, this is a dummy request waiting for a stateful helper to become available */
    struct timeval dispatch_time;
};

} // namespace Helper

MEMPROXY_CLASS_INLINE(Helper::Request);

#endif /* _SQUID_SRC_HELPER_REQUEST_H */

