/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_OIO_AIO_WIN32_H
#define SQUID_SRC_DISKIO_OIO_AIO_WIN32_H

#if HAVE_DISKIO_MODULE_OIO

#ifndef off64_t
typedef int64_t off64_t;
#endif

union sigval {
    int sival_int; /* integer value */
    void *sival_ptr; /* pointer value */
};

struct sigevent {
    int sigev_notify; /* notification mode */
    int sigev_signo; /* signal number */
    union sigval sigev_value; /* signal value */
};

struct aiocb {
    int aio_fildes; /* file descriptor */
    void *aio_buf; /* buffer location */
    size_t aio_nbytes; /* length of transfer */
#if (_FILE_OFFSET_BITS == 64)
    off64_t aio_offset; /* file offset */
#else
    off_t aio_offset; /* file offset */
#endif

    int aio_reqprio; /* request priority offset */

    struct sigevent aio_sigevent; /* signal number and offset */
    int aio_lio_opcode; /* listio operation */
};

#endif /* HAVE_DISKIO_MODULE_OIO */
#endif /* SQUID_SRC_DISKIO_OIO_AIO_WIN32_H */
