/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef SQUID_SRC_COMMONPOOL_H
#define SQUID_SRC_COMMONPOOL_H

#if USE_DELAY_POOLS
#include "CompositePoolNode.h"
#include "sbuf/SBuf.h"

/*
 \ingroup DelayPoolsAPI
 *
 * TODO: Next steps: make this a composite, and TypeLabel a composite method.
 * Then we have a legacy composite which returns class 1/2/3, and new
 * composites which return a descriptor of some sort.
 */
class CommonPool
{
    MEMPROXY_CLASS(CommonPool);

public:
    static CommonPool *Factory (unsigned char _class, CompositePoolNode::Pointer&);
    const SBuf &classTypeLabel() const { return typeLabel; }

protected:
    CommonPool();
    SBuf typeLabel;
};

#endif /* USE_DELAY_POOLS */
#endif /* SQUID_SRC_COMMONPOOL_H */

