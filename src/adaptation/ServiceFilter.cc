/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "adaptation/ServiceFilter.h"
#include "HttpReply.h"
#include "HttpRequest.h"

Adaptation::ServiceFilter::ServiceFilter(Method aMethod, VectPoint aPoint, HttpRequest *aReq, HttpReply *aRep, AccessLogEntry::Pointer const &alp):
    method(aMethod),
    point(aPoint),
    request(aReq),
    reply(aRep),
    al(alp)
{
    if (reply)
        HTTPMSGLOCK(reply);

    // a lot of code assumes that there is always a virgin request or cause
    assert(request);
    HTTPMSGLOCK(request);
}

Adaptation::ServiceFilter::ServiceFilter(const ServiceFilter &f):
    method(f.method),
    point(f.point),
    request(f.request),
    reply(f.reply),
    al(f.al)
{
    if (request)
        HTTPMSGLOCK(request);

    if (reply)
        HTTPMSGLOCK(reply);
}

Adaptation::ServiceFilter::~ServiceFilter()
{
    HTTPMSGUNLOCK(request);
    HTTPMSGUNLOCK(reply);
}

Adaptation::ServiceFilter &Adaptation::ServiceFilter::operator =(const ServiceFilter &f)
{
    if (this != &f) {
        method = f.method;
        point = f.point;
        HTTPMSGUNLOCK(request);
        HTTPMSGUNLOCK(reply);
        request = f.request;
        HTTPMSGLOCK(request);
        reply = f.reply;
        if (reply)
            HTTPMSGLOCK(reply);
    }
    return *this;
}

