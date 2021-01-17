/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_MEMSET_S_H
#define SQUID_COMPAT_MEMSET_S_H

#if !HAVE_MEMSET_S

typedef int errno_t;
typedef size_t rsize_t;

errno_t memset_s(void *dst, rsize_t dsz, int c, rsize_t len);

#endif
#endif /* SQUID_COMPAT_MEMSET_S_H */

