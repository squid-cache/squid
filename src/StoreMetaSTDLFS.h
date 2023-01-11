/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETASTDLFS_H
#define SQUID_STOREMETASTDLFS_H

#include "StoreMeta.h"

class StoreMetaSTDLFS : public StoreMeta
{
    MEMPROXY_CLASS(StoreMetaSTDLFS);

public:
    char getType() const {return STORE_META_STD_LFS;}

    bool validLength(int) const;
    //    bool checkConsistency(StoreEntry *) const;
};

#endif /* SQUID_STOREMETASTDLFS_H */

