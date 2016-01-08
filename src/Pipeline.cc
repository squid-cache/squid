/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "http/StreamContext.h"
#include "Pipeline.h"

void
Pipeline::add(const Http::StreamContextPointer &c)
{
    requests.push_back(c);
    ++nrequests;
    ++nactive;
    debugs(33, 3, "Pipeline " << (void*)this << " add request " << nrequests << ' ' << c);
}

Http::StreamContextPointer
Pipeline::front() const
{
    if (requests.empty()) {
        debugs(33, 3, "Pipeline " << (void*)this << " empty");
        return Http::StreamContextPointer();
    }

    debugs(33, 3, "Pipeline " << (void*)this << " front " << requests.front());
    return requests.front();
}

void
Pipeline::terminateAll(int xerrno)
{
    while (!requests.empty()) {
        Http::StreamContextPointer context = requests.front();
        debugs(33, 3, "Pipeline " << (void*)this << " notify(" << xerrno << ") " << context);
        context->noteIoError(xerrno);
        context->finished();  // cleanup and self-deregister
        assert(context != requests.front());
    }
}

void
Pipeline::popById(uint32_t which)
{
    if (requests.empty())
        return;

    debugs(33, 3, "Pipeline " << (void*)this << " drop id=" << which);

    // find the context and clear its Pointer
    for (auto &&i : requests) {
        if (i->id == which) {
            i = nullptr;
            --nactive;
            break;
        }
    }

    // trim closed contexts from the list head (if any)
    while (!requests.empty() && !requests.front())
        requests.pop_front();
}

