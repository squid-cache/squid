/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAOBJSIZE_H
#define SQUID_STOREMETAOBJSIZE_H

#include "StoreMeta.h"

class StoreMetaObjSize : public StoreMeta
{
    MEMPROXY_CLASS(StoreMetaObjSize);

public:
    char getType() const {return STORE_META_OBJSIZE;}
};

#endif /* SQUID_STOREMETAOBJSIZE_H */

