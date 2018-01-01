/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DELAYBUCKET_H
#define SQUID_DELAYBUCKET_H

class DelaySpec;
class StoreEntry;

/* don't use remote storage for these */

/// \ingroup DelayPoolsAPI
class DelayBucket
{

public:
    DelayBucket() : level_(0) {}

    int const& level() const {return level_;}

    int & level() {return level_;}

    void stats(StoreEntry *)const;
    void update (DelaySpec const &, int incr);
    int bytesWanted (int min, int max) const;
    void bytesIn(int qty);
    void init (DelaySpec const &);

private:
    int level_;
};

#endif /* SQUID_DELAYBUCKET_H */

