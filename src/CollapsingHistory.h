/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COLLAPSING_HISTORY_H
#define SQUID_COLLAPSING_HISTORY_H

/// collapsed forwarding history of a master transaction
class CollapsingHistory
{
public:
    /// whether at least one request was collapsed
    bool collapsed() const { return revalidationCollapses || otherCollapses; }

    /* These stats count collapsing decisions, regardless of their outcome. */

    /// the total number of collapsed internal revalidation requests
    int revalidationCollapses = 0;
    /// the total number of all other (a.k.a. "classic") collapsed requests
    int otherCollapses = 0;
};

#endif /* SQUID_COLLAPSING_HISTORY_H */

