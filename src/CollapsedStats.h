/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COLLAPSED_STATS_H
#define SQUID_COLLAPSED_STATS_H

/// Stats how many collapsed requests a transaction client participated in.
class CollapsedStats
{
    public:

        bool isCollapsed() const { return collapsed || revalidationCollapsed; }

        /// common CF counter
        int collapsed = 0;
        /// revalidation CF counter
        int revalidationCollapsed = 0;
};

#endif
