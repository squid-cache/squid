/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#ifndef SQUID_BLOCKINGIOSTRATEGY_H
#define SQUID_BLOCKINGIOSTRATEGY_H
#include "DiskIO/DiskIOStrategy.h"

class BlockingIOStrategy : public DiskIOStrategy
{

public:
    virtual bool shedLoad();
    virtual int load();
    virtual RefCount<DiskFile> newFile(char const *path);
    virtual bool unlinkdUseful() const;
    virtual void unlinkFile (char const *);
};

#endif /* SQUID_BLOCKINGIOSTRATEGY_H */

