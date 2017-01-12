/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
    virtual void init();
    virtual void gracefulShutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static MmappedDiskIOModule Instance;
};

#endif /* SQUID_MMAPPEDDISKIOMODULE_H */

