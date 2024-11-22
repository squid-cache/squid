/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 06    Disk I/O Routines */

#ifndef SQUID_SRC_FS_IO_H
#define SQUID_SRC_FS_IO_H

#include "mem/forward.h"
#include "sbuf/forward.h"
#include "typedefs.h" //DRCB, DWCB

class MemBuf;

class dread_ctrl
{
    MEMPROXY_CLASS(dread_ctrl);
public:
    dread_ctrl(int aFd, off_t aOffset, char *aBuf, int aLen, DRCB *aHandler, void *aData) :
        fd(aFd),
        offset(aOffset),
        req_len(aLen),
        buf(aBuf),
        handler(aHandler),
        client_data(aData)
    {}
    dread_ctrl(dread_ctrl &&) = delete; // no copying or moving of any kind
    ~dread_ctrl() = default;

    int fd = -1;
    off_t offset = 0;
    int req_len = 0;
    char *buf = nullptr;
    int end_of_file = 0;
    DRCB *handler = nullptr;
    void *client_data = nullptr;
};

class dwrite_q
{
    MEMPROXY_CLASS(dwrite_q);
public:
    dwrite_q(const size_t wantCapacity) : dwrite_q(wantCapacity, nullptr, nullptr) {}
    dwrite_q(size_t, char *, FREE *);
    dwrite_q(dwrite_q &&) = delete; // no copying or moving of any kind
    ~dwrite_q();

    off_t file_offset = 0;
    char *buf = nullptr;
    size_t len = 0; ///< length of content in buf
    size_t buf_offset = 0;
    dwrite_q *next = nullptr;

private:
    size_t capacity = 0; ///< allocation size of buf
    /// when set, gets called upon object destruction to free buf
    FREE *free_func = nullptr;
};

int file_open(const char *path, int mode);
void file_close(int fd);
void file_write(int, off_t, void const *, int len, DWCB *, void *, FREE *);
void file_read(int, char *, int, off_t, DRCB *, void *);
void safeunlink(const char *path, int quiet);

/*
 * Wrapper for rename(2) which complains if something goes wrong;
 * the caller is responsible for handing and explaining the
 * consequences of errors.
 *
 * \retval true successful rename
 * \retval false an error occurred
 */
bool FileRename(const SBuf &from, const SBuf &to);

int fsBlockSize(const char *path, int *blksize);
int fsStats(const char *, int *, int *, int *, int *);

#endif /* SQUID_SRC_FS_IO_H */

