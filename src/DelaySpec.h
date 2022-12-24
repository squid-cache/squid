/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DELAYSPEC_H
#define SQUID_DELAYSPEC_H

class StoreEntry;

/// \ingroup DelyPoolsAPI
class DelaySpec
{

public:
    DelaySpec();
    void stats(StoreEntry * sentry, char const *) const;
    void dump(StoreEntry *) const;
    void parse();
    int restore_bps;
    int64_t max_bytes;
};

#endif /* SQUID_DELAYSPEC_H */

