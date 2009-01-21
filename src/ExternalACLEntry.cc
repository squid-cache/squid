
/*
 * $Id$
 *
 * DEBUG: section 82    External ACL
 * AUTHOR: Henrik Nordstrom, MARA Systems AB
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  The contents of this file is Copyright (C) 2002 by MARA Systems AB,
 *  Sweden, unless otherwise is indicated in the specific function. The
 *  author gives his full permission to include this file into the Squid
 *  software product under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "ExternalACLEntry.h"
#include "SquidTime.h"

/******************************************************************
 * external_acl cache
 */

CBDATA_CLASS_INIT(ExternalACLEntry);

void *
ExternalACLEntry::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ExternalACLEntry));
    CBDATA_INIT_TYPE(ExternalACLEntry);
    return cbdataAlloc(ExternalACLEntry);
}

void
ExternalACLEntry::operator delete (void *address)
{
    cbdataFree (address);
}

ExternalACLEntry::ExternalACLEntry()
{
    lru.next = lru.prev = NULL;
    result = 0;
    date = 0;
    def = NULL;
}

ExternalACLEntry::~ExternalACLEntry()
{
    safe_free(key);
}

void
ExternalACLEntry::update(ExternalACLEntryData const &someData)
{
    date = squid_curtime;
    result = someData.result;

    user = someData.user;
    password = someData.password;
    message = someData.message;
    tag = someData.tag;
    log = someData.log;
}
