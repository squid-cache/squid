/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef MESSAGEBUCKET_H
#define MESSAGEBUCKET_H

#if USE_DELAY_POOLS

#include "BandwidthBucket.h"
#include "base/RefCount.h"
#include "comm/forward.h"
#include "MessageDelayPools.h"

/// Limits Squid-to-client bandwidth for each matching response
class MessageBucket : public RefCountable, public BandwidthBucket
{
    MEMPROXY_CLASS(MessageBucket);

public:
    typedef RefCount<MessageBucket> Pointer;

    MessageBucket(const int speed, const int initialLevelPercent, const double sizeLimit, MessageDelayPool::Pointer pool);

    /* BandwidthBucket API */
    virtual int quota() override;
    virtual void scheduleWrite(Comm::IoCallback *state) override;
    virtual void reduceBucket(int len) override;

private:
    MessageDelayPool::Pointer theAggregate;
};

#endif /* USE_DELAY_POOLS */

#endif

