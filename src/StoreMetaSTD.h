/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETASTD_H
#define SQUID_STOREMETASTD_H

#include "StoreMeta.h"

class StoreMetaSTD : public StoreMeta
{
    MEMPROXY_CLASS(StoreMetaSTD);

public:
    char getType() const {return STORE_META_STD;}

    bool validLength(int) const;
    //    bool checkConsistency(StoreEntry *) const;
};

#endif /* SQUID_STOREMETASTD_H */

