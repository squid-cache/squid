/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if !HAVE_MEMSET_S

#include "compat/memset_s.h"

errno_t
memset_s(void *dst, rsize_t dsz, int c, rsize_t len)
{
    errno_t ret = 0;
    if (!dst)
	    return EINVAL;
    if (dsz > SIZE_MAX)
	    return E2BIG;
    if (len > dsz) {
	    len = dsz;
	    ret = EOVERFLOW;
    }

    /**
     * to zero a buffer in a more secure manner meant for a handful of purposes.
     * e.g. for password clearing matters.
     * The compiler can optimize away a memset call to gain performance here
     * making sure it does not occur.
     *
     * address in a volatile pointer avoid gcc's likes doing optimizations.
     * thus it is not mean as memset replacement which would cause a performance
     * drop.
     */
    void *(*volatile memset_fn)(void *, int, size_t) = &memset;
    (void)memset_fn(dst, c, len);
    return ret;
}
#endif
