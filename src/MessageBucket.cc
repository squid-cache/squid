/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "comm/Connection.h"
#include "DelayPools.h"
#include "fde.h"
#include "MessageBucket.h"

MessageBucket::MessageBucket(const int speed, const int initialLevelPercent,
                             const double sizeLimit, MessageDelayPool::Pointer pool) :
    BandwidthBucket(speed, initialLevelPercent, sizeLimit),
    theAggregate(pool) {}

int
MessageBucket::quota()
{
    refillBucket();
    theAggregate->refillBucket();
    if (theAggregate->noLimit())
        return bucketLevel;
    else if (noLimit())
        return theAggregate->level();
    else
        return min(bucketLevel, static_cast<double>(theAggregate->level()));
}

void
MessageBucket::reduceBucket(int len)
{
    BandwidthBucket::reduceBucket(len);
    theAggregate->bytesIn(len);
}

void
MessageBucket::scheduleWrite(Comm::IoCallback *state)
{
    fde *F = &fd_table[state->conn->fd];
    if (!F->writeQuotaHandler->selectWaiting) {
        F->writeQuotaHandler->selectWaiting = true;
        // message delay pools limit this write; see checkTimeouts()
        SetSelect(state->conn->fd, COMM_SELECT_WRITE, Comm::HandleWrite, state, 0);
    }
}

#endif /* USE_DELAY_POOLS */

