
/*
 * $Id: win32.cc,v 1.5 2002/06/25 11:43:34 hno Exp $
 *
 * * * * * * * * Legal stuff * * * * * * *
 *
 * (C) 2001 Guido Serassio <serassio@libero.it>,
 *   inspired by previous work by Romeo Anghelache & Eric Stern.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

/* This code compiles only CygWin & Windows NT Port */
#if defined(_SQUID_MSWIN_) || defined(_SQUID_CYGWIN_)
#include <windows.h>

static unsigned int GetOSVersion();

/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

static unsigned int
GetOSVersion()
{
    OSVERSIONINFO osvi;

    safe_free(WIN32_OS_string);
    memset(&osvi, '\0', sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx((OSVERSIONINFO *) & osvi);
    switch (osvi.dwPlatformId) {
    case VER_PLATFORM_WIN32_NT:
	if (osvi.dwMajorVersion <= 4) {
	    WIN32_OS_string = xstrdup("Windows NT");
	    return _WIN_OS_WINNT;
	}
	if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 0)) {
	    WIN32_OS_string = xstrdup("Windows 2000");
	    return _WIN_OS_WIN2K;
	}
	if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1)) {
	    WIN32_OS_string = xstrdup("Windows XP");
	    return _WIN_OS_WINXP;
	}
	if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 2)) {
	    WIN32_OS_string = xstrdup("Windows .NET");
	    return _WIN_OS_WINNET;
	}
	break;
    case VER_PLATFORM_WIN32_WINDOWS:
	if ((osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion == 0)) {
	    WIN32_OS_string = xstrdup("Windows 95");
	    return _WIN_OS_WIN95;
	}
	if ((osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion == 10)) {
	    WIN32_OS_string = xstrdup("Windows 98");
	    return _WIN_OS_WIN98;
	}
	if ((osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion == 90)) {
	    WIN32_OS_string = xstrdup("Windows Me");
	    return _WIN_OS_WINME;
	}
	break;
    case VER_PLATFORM_WIN32s:
	WIN32_OS_string = xstrdup("Windows 3.1 with WIN32S");
	return _WIN_OS_WIN32S;
	break;
    default:
	break;
    }
    WIN32_OS_string = xstrdup("Unknown Windows system");
    return _WIN_OS_UNKNOWN;
}

/* ====================================================================== */
/* PUBLIC FUNCTIONS */
/* ====================================================================== */

void
WIN32_Exit()
{
    _exit(0);
}

int
WIN32_Subsystem_Init()
{
    WIN32_OS_version = GetOSVersion();
    if ((WIN32_OS_version == _WIN_OS_UNKNOWN) || (WIN32_OS_version == _WIN_OS_WIN32S))
	return 1;
    if (atexit(WIN32_Exit) != 0)
	return 1;
    return 0;
}
#endif
