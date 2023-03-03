/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMPAT_H
#define _SQUID_COMPAT_H

/*
 * From discussions it was chosen to push compat code as far down as possible.
 * That means we can have a separate compat for most
 *  compatibility and portability hacks and resolutions.
 *
 * This file is meant to collate all those hacks files together and
 * provide a simple include for them in the core squid headers
 * (presently squid.h)
 *
 * It should not be included directly in any of the squid sources.
 * If your code requires any symbols from here you should be importing
 * squid.h at the top line of your .cc file.
 */

/******************************************************/
/* Define the _SQUID_TYPE_ based on a guess of the OS */
/* NP: this MUST come first within compat.h           */
/******************************************************/
#include "compat/osdetect.h"

/* Solaris 10 has a broken definition for minor_t in IPFilter compat.
 * We must pre-define before doing anything with OS headers so the OS
 * do not. Then un-define it before using the IPFilter *_compat.h headers.
 */
#if IPF_TRANSPARENT && USE_SOLARIS_IPFILTER_MINOR_T_HACK
/* But we only need do this nasty thing for src/ip/Intercept.cc */
#if BUILDING_SQUID_IP_INTERCEPT_CC
#define minor_t solaris_minor_t_fubar
#endif
#endif

/*****************************************************/
/* FDSETSIZE is messy and needs to be done before    */
/* sys/types.h are defined.                          */
/*****************************************************/
#include "compat/fdsetsize.h"

/*****************************************************/
/* Global type re-definitions                        */
/* this also takes care of the basic system includes */
/*****************************************************/

/** On linux this must be defined to get PRId64 and friends */
#define __STDC_FORMAT_MACROS

#include "compat/types.h"

/*****************************************************/
/* per-OS hacks. One file per OS.                    */
/* OS-macro wrapping should be done inside the OS .h */
/*****************************************************/

#include "compat/os/aix.h"
#include "compat/os/android.h"
#include "compat/os/dragonfly.h"
#include "compat/os/freebsd.h"
#include "compat/os/hpux.h"
#include "compat/os/linux.h"
#include "compat/os/macosx.h"
#include "compat/os/mswindows.h"
#include "compat/os/netbsd.h"
#include "compat/os/openbsd.h"
#include "compat/os/os2.h"
#include "compat/os/qnx.h"
#include "compat/os/sgi.h"
#include "compat/os/solaris.h"
#include "compat/os/sunos.h"

/*****************************************************/
/* portabilities shared between all platforms and    */
/* components as found to be needed                  */
/*****************************************************/

#include "compat/assert.h"
#include "compat/compat_shared.h"
#include "compat/getaddrinfo.h"
#include "compat/getnameinfo.h"
#include "compat/inet_ntop.h"
#include "compat/inet_pton.h"
#include "compat/stdvarargs.h"

/* cstdio has a bunch of problems with 64-bit definitions */
#include "compat/stdio.h"

/* POSIX statvfs() is still not universal */
#include "compat/statvfs.h"

/*****************************************************/
/* component-specific portabilities                  */
/*****************************************************/

/* helper debugging requires some hacks to be clean */
#include "compat/debug.h"

/* Valgrind API macros changed between two versions squid supports */
#include "compat/valgrind.h"

#endif /* _SQUID_COMPAT_H */

