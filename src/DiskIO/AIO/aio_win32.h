/*
 * $Id$
 *
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef __WIN32_AIO_H__
#define __WIN32_AIO_H__

#include "config.h"

#if USE_DISKIO_AIO

#ifdef _SQUID_CYGWIN_
#include "squid_windows.h"
#endif

#ifndef off64_t
typedef int64_t	off64_t;
#endif

#ifdef _SQUID_MSWIN_

union sigval {
    int sival_int; /* integer value */
    void *sival_ptr; /* pointer value */
};

struct sigevent {
    int sigev_notify; /* notification mode */
    int sigev_signo; /* signal number */
    union sigval sigev_value; /* signal value */
};

// #endif

struct aiocb64 {
    int aio_fildes; /* file descriptor */
    void *aio_buf; /* buffer location */
    size_t aio_nbytes; /* length of transfer */
    off64_t aio_offset; /* file offset */
    int aio_reqprio; /* request priority offset */

    struct sigevent aio_sigevent; /* signal number and offset */
    int aio_lio_opcode; /* listio operation */
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

int aio_read(struct aiocb *);

int aio_write(struct aiocb *);

ssize_t aio_return(struct aiocb *);

int aio_error(const struct aiocb *);

int aio_read64(struct aiocb64 *);

int aio_write64(struct aiocb64 *);

ssize_t aio_return64(struct aiocb64 *);

int aio_error64(const struct aiocb64 *);
int aio_open(const char *, int);
void aio_close(int);

#endif /* _SQUID_MSWIN_ */
#endif /* USE_DISKIO_AIO */
#endif /* __WIN32_AIO_H__ */
