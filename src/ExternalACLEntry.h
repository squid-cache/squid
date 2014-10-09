
/*
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

#ifndef SQUID_EXTERNALACLENTRY_H
#define SQUID_EXTERNALACLENTRY_H

#include "acl/Acl.h"
#include "acl/forward.h"
#include "hash.h"
#include "Notes.h"
#include "SquidString.h"

class external_acl;
/******************************************************************
 * ExternalACLEntryData
 * Core data that ExternalACLEntry manages.
 * Not meant to be used as remote storage at any point:
 * stack or static or composition use only.
 */

class ExternalACLEntryData
{

public:
    ExternalACLEntryData() : result(ACCESS_DUNNO) {}

    allow_t result;

    /// list of all kv-pairs returned by the helper
    NotePairs notes;

#if USE_AUTH
    // TODO use an AuthUser to hold this info
    String user;
    String password;
#endif
    String message;
    String tag;
    String log;
};

/*******************************************************************
 * external_acl cache entry
 * Used opaqueue in the interface
 */

class ExternalACLEntry: public hash_link, public RefCountable
{
public:
    ExternalACLEntry();
    ~ExternalACLEntry();

    void update(ExternalACLEntryData const &);
    dlink_node lru;
    allow_t result;
    time_t date;

    /// list of all kv-pairs returned by the helper
    NotePairs notes;

#if USE_AUTH
    String user;
    String password;
#endif
    String message;
    String tag;
    String log;
    external_acl *def;

    MEMPROXY_CLASS(ExternalACLEntry);
};

MEMPROXY_CLASS_INLINE(ExternalACLEntry);

#endif
