#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_MINGW_H
#define SQUID_OS_MINGW_H

#if _SQUID_MINGW_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

// Nothing ported out of compat/os/mswin.h and compat/os/windows.h
// TODO: build and see what needs to be copied in here.

typedef unsigned char boolean;
typedef unsigned char u_char;
typedef unsigned int u_int;

#endif /* _SQUID_MINGW_ */
#endif /* SQUID_OS_MINGW_H */
