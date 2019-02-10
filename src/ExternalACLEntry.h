/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 82    External ACL */

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
 * Used opaque in the interface
 */

class ExternalACLEntry: public hash_link, public RefCountable
{
    MEMPROXY_CLASS(ExternalACLEntry);

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
};

#endif

