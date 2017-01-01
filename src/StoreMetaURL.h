/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAURL_H
#define SQUID_STOREMETAURL_H

/* for inheritance */
#include "StoreMeta.h"
/* for MEMPROXY_CLASS() macros */
#include "MemPool.h"

class StoreMetaURL : public StoreMeta
{
public:
    MEMPROXY_CLASS(StoreMetaURL);

    char getType() const {return STORE_META_URL;}

    bool checkConsistency(StoreEntry *) const;
};

MEMPROXY_CLASS_INLINE(StoreMetaURL);

#endif /* SQUID_STOREMETAURL_H */

