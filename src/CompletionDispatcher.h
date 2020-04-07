/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPLETIONDISPATCHER_H
#define SQUID_COMPLETIONDISPATCHER_H

/* Dispatch code to handle events that have completed. Completed events are queued
 * with a completion dispatcher by the OS Async engine - i.e. the poll or kqueue or
 * select loop, or a signal receiver, or the diskd/diskthreads/etc modules.
 */

class CompletionDispatcher
{

public:

    virtual ~CompletionDispatcher() {}

    /* dispatch events. This should return true if there were events dispatched
     * between the last call to dispatch() returning and this call returning.
     */
    virtual bool dispatch() = 0;
};

#endif /* SQUID_COMPLETIONDISPATCHER_H */

