/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AIODISKIOMODULE_H
#define SQUID_AIODISKIOMODULE_H

#if HAVE_DISKIO_MODULE_AIO

#include "DiskIO/DiskIOModule.h"

class AIODiskIOModule : public DiskIOModule
{

public:
    static AIODiskIOModule &GetInstance();
    AIODiskIOModule();
    virtual void init();
    virtual void gracefulShutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static AIODiskIOModule Instance;
};

#endif /* HAVE_DISKIO_MODULE_AIO */
#endif /* SQUID_AIODISKIOMODULE_H */

