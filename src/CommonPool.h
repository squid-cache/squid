/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef COMMONPOOL_H
#define COMMONPOOL_H

#if USE_DELAY_POOLS
#include "CompositePoolNode.h"
#include "SquidString.h"

/*
 \ingroup DelayPoolsAPI
 *
 \todo Next steps: make this a composite, and TypeLabel a composite method.
 * Then we have a legacy composite which returns class 1/2/3, and new
 * composites which return a descriptor of some sort.
 */
class CommonPool
{

public:
    void *operator new(size_t);
    void operator delete (void *);
    static CommonPool *Factory (unsigned char _class, CompositePoolNode::Pointer&);
    char const* theClassTypeLabel() const {return typeLabel.termedBuf();}

protected:
    CommonPool();
    String typeLabel;
};

#endif /* USE_DELAY_POOLS */
#endif /* COMMONPOOL_H */

