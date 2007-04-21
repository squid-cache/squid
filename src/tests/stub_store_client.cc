/*
 * $Id: stub_store_client.cc,v 1.2 2007/04/20 23:53:48 wessels Exp $
 *
 * DEBUG: section 84    Helper process maintenance
 * AUTHOR: Robert Collins
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
#include "StoreClient.h"
#include "Store.h"

int
storePendingNClients(const StoreEntry * e)
{
    /* no clients in the tests so far */
    return 0;
}

/* Garh, too many stub files */

void
StoreEntry::invokeHandlers()
{}

void
storeLog(int tag, const StoreEntry * e)
{
    /* do nothing for tests - we don't need the log */
}

void
storeLogOpen(void)
{
    fatal ("Not implemented");
}

void
storeDigestInit(void)
{
    fatal ("Not implemented");
}

void
storeRebuildStart(void)
{
    fatal ("Not implemented");
}

#include "Store.h"
const char *
storeEntryFlags(const StoreEntry *)
{
    fatal ("Not implemented");
    return NULL;
}

void
storeReplSetup(void)
{
    fatal ("Not implemented");
}

bool
store_client::memReaderHasLowerOffset(off_t anOffset) const
{
    fatal ("Not implemented");
    return false;
}

void
store_client::dumpStats(MemBuf * output, int clientNumber) const
{
    fatal ("Not implemented");
}

int
store_client::getType() const
{
    return type;
}

