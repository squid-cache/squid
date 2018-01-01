/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef DELAYPOOL_H
#define DELAYPOOL_H

#if USE_DELAY_POOLS
#include "acl/forward.h"
#include "CompositePoolNode.h"

class StoreEntry;

class CommonPool;

/// \ingroup DelayPoolsAPI
class DelayPool
{

public:
    DelayPool();
    ~DelayPool();
    void freeData();
    void createPool(u_char delay_class);
    void parse();
    void dump (StoreEntry *, unsigned int poolNumberMinusOne) const;
    CommonPool *pool;
    CompositePoolNode::Pointer theComposite() {return theComposite_;}

    CompositePoolNode::Pointer const theComposite() const {return theComposite_;}

    acl_access *access;

private:
    CompositePoolNode::Pointer theComposite_;
};

#endif /* USE_DELAY_POOLS */
#endif /* DELAYPOOL_H */

