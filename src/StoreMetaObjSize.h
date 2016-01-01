/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAOBJSIZE_H
#define SQUID_STOREMETAOBJSIZE_H

#include "MemPool.h"
#include "StoreMeta.h"

class StoreMetaObjSize : public StoreMeta
{

public:
    MEMPROXY_CLASS(StoreMetaObjSize);

    char getType() const {return STORE_META_OBJSIZE;}
};

MEMPROXY_CLASS_INLINE(StoreMetaObjSize);

#endif /* SQUID_STOREMETAOBJSIZE_H */

