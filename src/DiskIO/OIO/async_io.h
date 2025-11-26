/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_OIO_ASYNC_IO_H
#define SQUID_SRC_DISKIO_OIO_ASYNC_IO_H

#if HAVE_DISKIO_MODULE_OIO

#include "DiskIO/OIO/aio_win32.h"
#include "mem/forward.h"

#define MAX_ASYNCOP     128

typedef enum {
    AQ_STATE_NONE = 0, /* Not active/uninitialised */
    AQ_STATE_SETUP /* Initialised */
} async_queue_state_t;

typedef enum {
    AQ_ENTRY_FREE = 0,
    AQ_ENTRY_USED
} async_queue_entry_state_t;

typedef enum {
    AQ_ENTRY_NONE = 0,
    AQ_ENTRY_READ,
    AQ_ENTRY_WRITE
} async_queue_entry_type_t;

typedef struct _async_queue_entry async_queue_entry_t;

typedef struct _async_queue async_queue_t;

namespace DiskIO
{
namespace OIO
{
class File;
}
}

/* An async queue entry */
struct _async_queue_entry {
    async_queue_entry_state_t aq_e_state;
    async_queue_entry_type_t aq_e_type;

    struct aiocb aq_e_aiocb;
    DiskIO::OIO::File *theFile;
    void *aq_e_callback_data;
    FREE *aq_e_free;
    int aq_e_fd;
    void *aq_e_buf;
};

/* An async queue */
struct _async_queue {
    async_queue_state_t aq_state;
    async_queue_entry_t aq_queue[MAX_ASYNCOP];  /* queued ops */
    int aq_numpending;      /* Num of pending ops */
};

#endif /* HAVE_DISKIO_MODULE_OIO */
#endif /* SQUID_SRC_DISKIO_OIO_ASYNC_IO_H */
