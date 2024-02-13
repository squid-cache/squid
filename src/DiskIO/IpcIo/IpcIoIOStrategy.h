/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_IPCIO_IPCIOIOSTRATEGY_H
#define SQUID_SRC_DISKIO_IPCIO_IPCIOIOSTRATEGY_H
#include "DiskIO/DiskIOStrategy.h"

class IpcIoIOStrategy : public DiskIOStrategy
{

public:
    bool shedLoad() override;
    int load() override;
    RefCount<DiskFile> newFile(char const *path) override;
    bool unlinkdUseful() const override;
    void unlinkFile (char const *) override;
};

#endif /* SQUID_SRC_DISKIO_IPCIO_IPCIOIOSTRATEGY_H */

