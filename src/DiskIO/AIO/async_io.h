/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef __ASYNC_IO_H__
#define __ASYNC_IO_H__

#if USE_DISKIO_AIO

#if _SQUID_WINDOWS_
#include "aio_win32.h"
#else
#if HAVE_AIO_H
#include <aio.h>
#endif
#endif

/* for FREE* */
#include "typedefs.h"

#define MAX_ASYNCOP     128

typedef enum {
    AQ_STATE_NONE,      /* Not active/uninitialised */
    AQ_STATE_SETUP      /* Initialised */
} async_queue_state_t;

typedef enum {
    AQ_ENTRY_FREE,
    AQ_ENTRY_USED
} async_queue_entry_state_t;

typedef enum {
    AQ_ENTRY_NONE,
    AQ_ENTRY_READ,
    AQ_ENTRY_WRITE
} async_queue_entry_type_t;

typedef struct _async_queue_entry async_queue_entry_t;

typedef struct _async_queue async_queue_t;

/* An async queue entry */

class AIODiskFile;

struct _async_queue_entry {
    async_queue_entry_state_t aq_e_state;
    async_queue_entry_type_t aq_e_type;

    /* 64-bit environments with non-GCC complain about the type mismatch on Linux */
#if defined(__USE_FILE_OFFSET64) && !defined(__GNUC__)
    struct aiocb64 aq_e_aiocb;
#else
    struct aiocb aq_e_aiocb;
#endif
    AIODiskFile *theFile;
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

#endif /* USE_DISKIO_AIO */
#endif /* __ASYNC_IO_H_ */

