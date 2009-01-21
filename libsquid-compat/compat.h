#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef _SQUID_COMPAT_H
#define _SQUID_COMPAT_H

/*
 * From discussions it was chosen to push compat code as far down as possible.
 * That means we can have a seperate libsquid-compat for most
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
#include "osdetect.h"


/*****************************************************/
/* FDSETSIZE is messy and needs to be done before    */
/* sys/types.h are defined.                          */
/*****************************************************/
#include "squid_fdsetsize.h"


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

#include "os/squid_aix.h"
#include "os/squid_dragonfly.h"
#include "os/squid_freebsd.h"
#include "os/squid_hpux.h"
#include "os/squid_linux.h"
#include "os/squid_mswin.h"
#include "os/squid_next.h"
#include "os/squid_openbsd.h"
#include "os/squid_os2.h"
#include "os/squid_qnx.h"
#include "os/squid_sgi.h"
#include "os/squid_solaris.h"
#include "os/squid_sunos.h"
#include "os/squid_windows.h"


/*****************************************************/
/* portabilities shared between all platforms and    */
/* components as found to be needed                  */
/*****************************************************/

#include "compat_shared.h"
#include "squid_stdvarargs.h"
#include "assert.h"

/*****************************************************/
/* component-specific portabilities                  */
/*****************************************************/

/* Valgrind API macros changed between two versions squid supports */
#include "squid_valgrind.h"

/* Endian functions are usualy handled by the OS but not always. */
#include "squid_endian.h"

/**
 * A Regular Expression library is bundled with Squid.
 * Default is to use a system provided one, but the bundle
 * may be used instead with explicit configuration.
 */
#include "GnuRegex.h"


#endif /* _SQUID_COMPAT_H */
