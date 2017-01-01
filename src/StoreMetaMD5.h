/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAMD5_H
#define SQUID_STOREMETAMD5_H

/* for inheritance */
#include "StoreMeta.h"
/* for MEMPROXY_CLASS() macros */
#include "MemPool.h"
/* for STORE_META_KEY_MD5 */
#include "enums.h"

class StoreMetaMD5 : public StoreMeta
{

public:
    MEMPROXY_CLASS(StoreMetaMD5);

    char getType() const {return STORE_META_KEY_MD5;}

    bool validLength(int) const;
    bool checkConsistency(StoreEntry *) const;

private:
    static int md5_mismatches;
};

MEMPROXY_CLASS_INLINE(StoreMetaMD5);

#endif /* SQUID_STOREMETAMD5_H */

