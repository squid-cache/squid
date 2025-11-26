/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_OIO_STRATEGY_H
#define SQUID_SRC_DISKIO_OIO_STRATEGY_H

#if HAVE_DISKIO_MODULE_OIO

#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/OIO/async_io.h"

namespace DiskIO
{
namespace OIO
{

class Strategy : public DiskIOStrategy
{
public:
    Strategy();
    ~Strategy() override;

    /**
     * find a free queue slot.
     * \return the index, or -1 if we can't find one.
     */
    int findSlot();

    /* DiskIOStrategy API */
    bool shedLoad() override { return false; }
    int load() override;
    RefCount<DiskFile> newFile(char const *) override;
    void sync() override;
    bool unlinkdUseful() const override { return false; }
    void unlinkFile(char const *) override {}
    int callback() override { return 0; }
    void init() override;
    void statfs(StoreEntry &) const override {}
    ConfigOption *getOptionTree() const override { return nullptr; }

public:
    /// a file descriptor
    int fd = -1;
    /// queue of requests
    async_queue_t aq;
};

} // namespace OIO
} // namespace DiskIO

#endif /* HAVE_DISKIO_MODULE_OIO */
#endif /* SQUID_SRC_DISKIO_OIO_STRATEGY_H */
