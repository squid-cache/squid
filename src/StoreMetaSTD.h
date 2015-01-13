/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETASTD_H
#define SQUID_STOREMETASTD_H

#include "StoreMeta.h"
/* for MEMPROXY_CLASS() macros */
#include "MemPool.h"

class StoreMetaSTD : public StoreMeta
{

public:
    MEMPROXY_CLASS(StoreMetaSTD);

    char getType() const {return STORE_META_STD;}

    bool validLength(int) const;
    //    bool checkConsistency(StoreEntry *) const;
};

MEMPROXY_CLASS_INLINE(StoreMetaSTD);

#endif /* SQUID_STOREMETASTD_H */

