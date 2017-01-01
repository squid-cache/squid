/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAVARY_H
#define SQUID_STOREMETAVARY_H

#include "StoreMeta.h"

class StoreMetaVary : public StoreMeta
{
    MEMPROXY_CLASS(StoreMetaVary);

public:
    char getType() const {return STORE_META_VARY_HEADERS;}

    bool checkConsistency(StoreEntry *) const;
};

#endif /* SQUID_STOREMETAVARY_H */

