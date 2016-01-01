/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "psignal.h"

#if _SQUID_AIX_ || _SQUID_ANDROID_ || _SQUID_MINGW_
extern const char* const sys_siglist[];
#define _sys_nsig 64
#define _sys_siglist sys_siglist
#endif

/// purpose: print message, colon, space, signal name and LF.
/// paramtr: sig (IN): signal number
///          msg (IN): message to prepend
void
psignal( int sig, const char* msg )
{
    if ( msg && *msg ) fprintf( stderr, "%s: ", msg );
    if ( sig > 0 && sig < _sys_nsig )
        fprintf( stderr, "%s\n", _sys_siglist[sig] );
    else
        fputs( "(unknown)\n", stderr );
}

