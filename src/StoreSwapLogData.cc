/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
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

#include "StoreSwapLogData.h"

StoreSwapLogData::StoreSwapLogData(): op(0), swap_filen (0), timestamp (0), lastref (0), expires (0), lastmod(0), swap_file_sz (0), refcount (0), flags (0)
{
    memset (key, '\0', sizeof(key));
}

bool
StoreSwapLogData::sane() const
{
    // TODO: These checks are rather weak. A corrupted swap.state may still
    // cause havoc (e.g., cur_size may become astronomical). Add checksums?

    const time_t minTime = -2; // -1 is common; expires sometimes uses -2

    // Check what we safely can; for some fields any value might be valid
    return SWAP_LOG_NOP < op && op < SWAP_LOG_MAX &&
           swap_filen >= 0 &&
           timestamp >= minTime &&
           lastref >= minTime &&
           expires >= minTime &&
           lastmod >= minTime &&
           swap_file_sz > 0; // because swap headers ought to consume space
}

StoreSwapLogHeader::StoreSwapLogHeader():op(SWAP_LOG_VERSION), version(1)
{
    record_size = sizeof(StoreSwapLogData);
}
