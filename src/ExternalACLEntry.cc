/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 82    External ACL */

#include "squid.h"
#include "ExternalACLEntry.h"
#include "SquidTime.h"

/******************************************************************
 * external_acl cache
 */

ExternalACLEntry::ExternalACLEntry() :
    notes()
{
    lru.next = lru.prev = NULL;
    result = ACCESS_DENIED;
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

    // replace all notes. not combine
    notes.entries.clear();
    notes.append(&someData.notes);

#if USE_AUTH
    user = someData.user;
    password = someData.password;
#endif
    message = someData.message;
    tag = someData.tag;
    log = someData.log;
}

