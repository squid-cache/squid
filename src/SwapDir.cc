
/*
 * $Id: SwapDir.cc,v 1.1 2002/12/27 10:26:33 robertc Exp $
 *
 * DEBUG: section ??    Swap Dir base object
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
#include "SwapDir.h"
#include "Store.h"

SwapDir *
SwapDir::Factory (_storefs_entry const &fs)
{
    SwapDir *result = fs.newfunc();
    result->type = fs.typestr;
    return result;
}

SwapDir::~SwapDir() {
    xfree(path);
}

void
SwapDir::newFileSystem(){}

void
SwapDir::dump(StoreEntry &)const{}

bool
SwapDir::doubleCheck(StoreEntry &)
{
    return false;
}

void
SwapDir::unlink(StoreEntry &){}

void
SwapDir::statfs(StoreEntry &)const {}

void
SwapDir::maintainfs(){}

void
SwapDir::reference(StoreEntry &){}

void
SwapDir::dereference(StoreEntry &){}

int
SwapDir::callback()
{
    return 0;
}

void
SwapDir::sync(){}

/* Move to StoreEntry ? */
bool
SwapDir::canLog(StoreEntry const &e)const
{
    if (e.swap_filen < 0)
	return false;
    if (e.swap_status != SWAPOUT_DONE)
	return false;
    if (e.swap_file_sz <= 0)
	return false;
    if (EBIT_TEST(e.flags, RELEASE_REQUEST))
	return false;
    if (EBIT_TEST(e.flags, KEY_PRIVATE))
	return false;
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
	return false;
    return true;
}

void
SwapDir::openLog(){}

void
SwapDir::closeLog(){}

int
SwapDir::writeCleanStart()
{
    return 0;
}

void
SwapDir::writeCleanDone(){}

void
SwapDir::logEntry(const StoreEntry & e, int op) const{}
