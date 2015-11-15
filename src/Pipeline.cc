/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 33    Client Request Pipeline
 */
#include "squid.h"
#include "client_side.h"
#include "Debug.h"
#include "Pipeline.h"

void
Pipeline::add(const ClientSocketContextPointer &c)
{
    requests.push_back(c);
    ++nrequests;
    debugs(33, 3, "Pipeline " << (void*)this << " add request " << nrequests << ' ' << c);
}

ClientSocketContextPointer
Pipeline::front() const
{
    if (requests.empty()) {
        debugs(33, 3, "Pipeline " << (void*)this << " empty");
        return ClientSocketContextPointer();
    }

    debugs(33, 3, "Pipeline " << (void*)this << " front " << requests.front());
    return requests.front();
}

void
Pipeline::terminateAll(int xerrno)
{
    while (!requests.empty()) {
        ClientSocketContextPointer context = requests.front();
        debugs(33, 3, "Pipeline " << (void*)this << " notify(" << xerrno << ") " << context);
        context->noteIoError(xerrno);
        context->connIsFinished();  // cleanup and self-deregister
        assert(context != requests.front());
    }
}

void
Pipeline::pop()
{
    if (requests.empty())
        return;

    debugs(33, 3, "Pipeline " << (void*)this << " drop " << requests.front());
    requests.pop_front();
}

