/*
 * $Id$
 *
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef _INC_SQUID_WINDOWS_H
#define _INC_SQUID_WINDOWS_H

#include "config.h"

#ifdef _SQUID_WIN32_

#ifndef ACL
#define ACL WindowsACL
#define _MSWIN_ACL_WAS_NOT_DEFINED 1
#endif
#include <windows.h>
#if _MSWIN_ACL_WAS_NOT_DEFINED
#undef ACL
#undef _MSWIN_ACL_WAS_NOT_DEFINED
#endif

#endif /* _SQUID_WIN32_ */

#endif /* _INC_SQUID_WINDOWS_H */
