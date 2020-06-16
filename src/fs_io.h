/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 06    Disk I/O Routines */

#ifndef SQUID_FS_IO_H_
#define SQUID_FS_IO_H_

#include "mem/forward.h"
#include "sbuf/forward.h"
#include "typedefs.h" //DRCB, DWCB

class MemBuf;

// POD
class dread_ctrl
{
public:
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int end_of_file;
    DRCB *handler;
    void *client_data;
};

// POD
class dwrite_q
{
public:
    off_t file_offset;
    char *buf;
    size_t len;
    size_t buf_offset;
    dwrite_q *next;
    FREE *free_func;
};

int file_open(const char *path, int mode);
void file_close(int fd);
void file_write(int, off_t, void const *, int len, DWCB *, void *, FREE *);
void file_write_mbuf(int fd, off_t, MemBuf mb, DWCB * handler, void *handler_data);
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

#endif /* SQUID_FS_IO_H_ */

