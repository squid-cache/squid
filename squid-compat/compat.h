#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef _SQUID_COMPAT_H
#define _SQUID_COMPAT_H

/*
 * From discussions it was chosen to push compat code as far down as possible.
 * That means we can have a seperate squid-compat for most
 *  compatability and portability hacks and resolutions.
 * 
 * This file is meant to collate all those hacks files together and
 * provide a simple include for them in the core squid headers
 * (presently squid.h and config.h) 
 *
 * It should not be included directly in any of the squid sources.
 * If your code requires any symbols from here you should be importing
 * config.h/squid.h at the top line of your .cc or .h file.
 */


/******************************************************/
/* Define the _SQUID_TYPE_ based on a guess of the OS */
/* NP: this MUST come first within compat.h           */
/******************************************************/
#include "squid-compat/osdetect.h"


/*****************************************************/
/* FDSETSIZE is messy and needs to be done before    */
/* sys/types.h are defined.                          */
/*****************************************************/
#include "squid-compat/fdsetsize.h"


/*****************************************************/
/* Global type re-definitions                        */
/* this also takes care of the basic system includes */
/*****************************************************/

/** On linux this must be defined to get PRId64 and friends */
#define __STDC_FORMAT_MACROS

#include "squid_types.h"

/*****************************************************/
/* per-OS hacks. One file per OS.                    */
/* OS-macro wrapping should be done inside the OS .h */
/*****************************************************/

#include "squid-compat/os/aix.h"
#include "squid-compat/os/dragonfly.h"
#include "squid-compat/os/freebsd.h"
#include "squid-compat/os/hpux.h"
#include "squid-compat/os/linux.h"
#include "squid-compat/os/mswin.h"
#include "squid-compat/os/next.h"
#include "squid-compat/os/openbsd.h"
#include "squid-compat/os/os2.h"
#include "squid-compat/os/qnx.h"
#include "squid-compat/os/sgi.h"
#include "squid-compat/os/solaris.h"
#include "squid-compat/os/sunos.h"
#include "squid-compat/os/windows.h"


/*****************************************************/
/* portabilities shared between all platforms and    */
/* components as found to be needed                  */
/*****************************************************/

#include "squid-compat/compat_shared.h"
#include "squid-compat/stdvarargs.h"
#include "squid-compat/assert.h"

/*****************************************************/
/* component-specific portabilities                  */
/*****************************************************/

/* Valgrind API macros changed between two versions squid supports */
#include "squid-compat/valgrind.h"

/* Endian functions are usualy handled by the OS but not always. */
#include "squid_endian.h"

/**
 * A Regular Expression library is bundled with Squid.
 * Default is to use a system provided one, but the bundle
 * may be used instead with explicit configuration.
 */
#include "squid-compat/GnuRegex.h"


#endif /* _SQUID_COMPAT_H */
