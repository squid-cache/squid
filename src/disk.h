/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 06    Disk I/O Routines */

#ifndef SQUID_DISK_H_
#define SQUID_DISK_H_

#include "typedefs.h"

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

/* Adapter file_write for object callbacks */
template <class O>
void
FreeObject(void *address)
{
    O *anObject = static_cast <O *>(address);
    delete anObject;
}

void file_write(int, off_t, void const *, int len, DWCB *, void *, FREE *);
void file_write_mbuf(int fd, off_t, MemBuf mb, DWCB * handler, void *handler_data);
void file_read(int, char *, int, off_t, DRCB *, void *);
void disk_init(void);
void safeunlink(const char *path, int quiet);
int xrename(const char *from, const char *to); //disk.cc

#endif /* SQUID_DISK_H_ */

