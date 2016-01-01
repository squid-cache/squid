/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_OS_SGI_H
#define SQUID_OS_SGI_H

#if _SQUID_SGI_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

#if !defined(_SVR4_SOURCE)
#define _SVR4_SOURCE        /* for tempnam(3) */
#endif

#if USE_ASYNC_IO
#define _ABI_SOURCE
#endif /* USE_ASYNC_IO */

#if defined(__cplusplus) && !defined(_SQUID_EXTERNNEW_) && !defined(_GNUC_)
/*
 * The gcc compiler treats extern inline functions as being extern,
 * while the SGI MIPSpro compilers treat them as inline. To get equivalent
 * behavior, remove the inline keyword.
 */
#define _SQUID_EXTERNNEW_ extern
#endif

#endif /* _SQUID_SGI_ */
#endif /* SQUID_OS_SGI_H */

