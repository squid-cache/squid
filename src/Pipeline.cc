/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 33    Client Request Pipeline
 */
#include "squid.h"
#include "anyp/PortCfg.h"
#include "client_side.h"
#include "Debug.h"
#include "http/Stream.h"
#include "Pipeline.h"

void
Pipeline::add(const Http::StreamPointer &c)
{
    requests.push_back(c);
    ++nrequests;
    debugs(33, 3, "Pipeline " << (void*)this << " add request " << nrequests << ' ' << c);
}

Http::StreamPointer
Pipeline::front() const
{
    if (requests.empty()) {
        debugs(33, 3, "Pipeline " << (void*)this << " empty");
        return Http::StreamPointer();
    }

    debugs(33, 3, "Pipeline " << (void*)this << " front " << requests.front());
    return requests.front();
}

Http::StreamPointer
Pipeline::back() const
{
    if (requests.empty()) {
        debugs(33, 3, "Pipeline " << (void*)this << " empty");
        return Http::StreamPointer();
    }

    debugs(33, 3, "Pipeline " << (void*)this << " back " << requests.back());
    return requests.back();
}

void
Pipeline::terminateAll(const Error &error, const LogTagsErrors &lte)
{
    while (!requests.empty()) {
        Http::StreamPointer context = requests.front();
        debugs(33, 3, (void*)this << " terminates " << context << " with " << error);
        context->noteIoError(error, lte);
        context->finished();  // cleanup and self-deregister
        assert(context != requests.front());
    }
}

void
Pipeline::popMe(const Http::StreamPointer &which)
{
    if (requests.empty())
        return;

    debugs(33, 3, "Pipeline " << (void*)this << " drop " << requests.front());
    // in reality there may be multiple contexts doing processing in parallel.
    // XXX: pipeline still assumes HTTP/1 FIFO semantics are obeyed.
    assert(which == requests.front());
    requests.pop_front();
}

