#ifndef _SQUID_COMPAT_H
#define _SQUID_COMPAT_H

/*
 * From discussions it was chosen to push compat code as far down as possible.
 * That means we can have a seperate compat for most
 *  compatability and portability hacks and resolutions.
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

/* ugly hack. But we need to set this REALLY soon in the header */
#if _SQUID_SOLARIS_ && !defined(__GNUC__) && !defined(__GNUG__)
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 1
#endif
#ifndef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED 1
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
#include "compat/os/next.h"
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

#include "compat/compat_shared.h"
#include "compat/stdvarargs.h"
#include "compat/assert.h"

/* cstdio has a bunch of problems with 64-bit definitions */
#include "compat/stdio.h"

/*****************************************************/
/* component-specific portabilities                  */
/*****************************************************/

/* helper debugging requires some hacks to be clean */
#include "compat/debug.h"

/* Valgrind API macros changed between two versions squid supports */
#include "compat/valgrind.h"

/* Endian functions are usualy handled by the OS but not always. */
#include "squid_endian.h"

/**
 * A Regular Expression library is bundled with Squid.
 * Default is to use a system provided one, but the bundle
 * may be used instead with explicit configuration.
 */
#include "compat/GnuRegex.h"

/* cppunit is not quite C++0x compatible yet */
#include "compat/cppunit.h"

#endif /* _SQUID_COMPAT_H */
