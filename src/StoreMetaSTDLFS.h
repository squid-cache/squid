/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETASTDLFS_H
#define SQUID_STOREMETASTDLFS_H

/* for inheritance */
#include "StoreMeta.h"
/* for MEMPROXY() macros */
#include "MemPool.h"

class StoreMetaSTDLFS : public StoreMeta
{
public:
    MEMPROXY_CLASS(StoreMetaSTDLFS);

    char getType() const {return STORE_META_STD_LFS;}

    bool validLength(int) const;
    //    bool checkConsistency(StoreEntry *) const;
};

MEMPROXY_CLASS_INLINE(StoreMetaSTDLFS);

#endif /* SQUID_STOREMETASTDLFS_H */

