/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_IODISKIOMODULE_H
#define SQUID_IPC_IODISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class IpcIoDiskIOModule : public DiskIOModule
{

public:
    static IpcIoDiskIOModule &GetInstance();
    IpcIoDiskIOModule();
    void init() override;
    void gracefulShutdown() override;
    char const *type () const override;
    DiskIOStrategy* createStrategy() override;

private:
    static IpcIoDiskIOModule Instance;
};

#endif /* SQUID_IPC_IODISKIOMODULE_H */

