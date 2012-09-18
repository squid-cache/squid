/*
 * DEBUG: section 73    HTTP Request
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

#include "squid.h"
#include "Debug.h"
#include "RequestFlags.h"

// TODO: move to .cci
/* RequestFlags */
bool
RequestFlags::resetTCP() const
{
    return resetTCP_;
}

void
RequestFlags::setResetTCP()
{
    debugs(73, 9, "request_flags::setResetTCP");
    resetTCP_ = true;
}

void
RequestFlags::clearResetTCP()
{
    debugs(73, 9, "request_flags::clearResetTCP");
    resetTCP_ = false;
}

void
RequestFlags::destinationIPLookupCompleted()
{
    destinationIPLookedUp_ = true;
}

bool
RequestFlags::destinationIPLookedUp() const
{
    return destinationIPLookedUp_;
}

bool
RequestFlags::isRanged() const
{
    return isRanged_;
}

void
RequestFlags::setRanged()
{
    isRanged_ = true;
}

void
RequestFlags::clearRanged()
{
    isRanged_ = false;
}

RequestFlags
RequestFlags::cloneAdaptationImmune() const
{
    // At the time of writing, all flags where either safe to copy after
    // adaptation or were not set at the time of the adaptation. If there
    // are flags that are different, they should be cleared in the clone.
    return *this;
}
