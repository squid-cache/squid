/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAURL_H
#define SQUID_STOREMETAURL_H

#include "StoreMeta.h"

class StoreMetaURL : public StoreMeta
{
    MEMPROXY_CLASS(StoreMetaURL);

public:
    char getType() const {return STORE_META_URL;}

    bool checkConsistency(StoreEntry *) const;
};

#endif /* SQUID_STOREMETAURL_H */

