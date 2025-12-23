/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_OIO_FILE_H
#define SQUID_SRC_DISKIO_OIO_FILE_H

#if HAVE_DISKIO_MODULE_OIO

#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/OIO/async_io.h"
#include "SquidString.h"

namespace DiskIO
{
namespace OIO
{

class Strategy;

class File : public DiskFile
{
    CBDATA_CLASS(File);

public:
    friend class DiskIO::OIO::Strategy;

    File(char const *path, Strategy *);
    ~File() override;

    /* DiskFile API */
    void open(int, mode_t, IORequestor::Pointer) override;
    void create(int, mode_t, IORequestor::Pointer) override;
    void read(ReadRequest *) override;
    void write(WriteRequest *) override;
    void close() override;
    bool canRead() const override { return true; }
    int getFD() const override { return fd; }
    bool error() const override { return error_; }
    bool ioInProgress() const override { return false; }

private:
    void error(bool const &e) { error_ = e; }

    int fd = -1;
    String path;
    Strategy *strategy = nullptr;
    IORequestor::Pointer ioRequestor;
    bool closed = true;
    bool error_ = false;
};

} // namespace OIO
} // namespace DiskIO

#endif /* HAVE_DISKIO_MODULE_OIO */
#endif /* SQUID_SRC_DISKIO_OIO_FILE_H */
