/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_POLL || USE_SELECT
#include "comm/Incoming.h"

void
Comm::Incoming::finishPolling(int n, SquidConfig::CommIncoming::Measure &cfg)
{
    if (n < 0)
        return;

    interval += cfg.average - n;

    if (interval < cfg.min_poll)
        interval = cfg.min_poll;

    if (interval > MaxInterval)
        interval = MaxInterval;

    if (n > nMaximum)
        n = nMaximum;

    history.count(n);
}

#endif /* USE_POLL || USE_SELECT */
