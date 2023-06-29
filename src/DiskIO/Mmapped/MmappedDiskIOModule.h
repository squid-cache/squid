/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MMAPPEDDISKIOMODULE_H
#define SQUID_MMAPPEDDISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class MmappedDiskIOModule : public DiskIOModule
{

public:
    static MmappedDiskIOModule &GetInstance();
    MmappedDiskIOModule();
    void init() override;
    void gracefulShutdown() override;
    char const *type () const override;
    DiskIOStrategy* createStrategy() override;

private:
    static MmappedDiskIOModule Instance;
};

#endif /* SQUID_MMAPPEDDISKIOMODULE_H */

