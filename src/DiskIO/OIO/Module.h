/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_OIO_MODULE_H
#define SQUID_SRC_DISKIO_OIO_MODULE_H

#if HAVE_DISKIO_MODULE_OIO

#include "DiskIO/DiskIOModule.h"

namespace DiskIO
{
/// Windows Overlapped I/O module for Disk I/O
namespace OIO
{

class Module : public DiskIOModule
{
public:
    static Module &GetInstance();
    Module();

    /* DiskIOModule API */
    void init() override {}
    void gracefulShutdown() override {}
    DiskIOStrategy* createStrategy() override;
    char const *type() const override { return "OIO"; }
};

} // namespace OIO
} // namespace DiskIO

#endif /* HAVE_DISKIO_MODULE_OIO */
#endif /* SQUID_SRC_DISKIO_OIO_MODULE_H */
