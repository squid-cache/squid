/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

#endif /* _SQUID_SGI_ */
#endif /* SQUID_OS_SGI_H */

