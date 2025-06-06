/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#ifndef SQUID_SRC_DISKIO_BLOCKING_BLOCKINGIOSTRATEGY_H
#define SQUID_SRC_DISKIO_BLOCKING_BLOCKINGIOSTRATEGY_H
#include "DiskIO/DiskIOStrategy.h"

class BlockingIOStrategy : public DiskIOStrategy
{

public:
    bool shedLoad() override;
    int load() override;
    RefCount<DiskFile> newFile(char const *path) override;
    bool unlinkdUseful() const override;
    void unlinkFile (char const *) override;
};

#endif /* SQUID_SRC_DISKIO_BLOCKING_BLOCKINGIOSTRATEGY_H */

