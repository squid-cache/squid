/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "base/PackableStream.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "globals.h"
#include "helper/ChildConfig.h"
#include "Parsing.h"
#include "parser/Tokenizer.h"
#include "sbuf/List.h"
#include "Store.h"

#include <cstring>

Helper::ChildConfig::ChildConfig():
    n_max(0),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0),
    queue_size(0),
    onPersistentOverload(actDie),
    defaultQueueSize(true)
{}

Helper::ChildConfig::ChildConfig(const unsigned int m):
    n_max(m),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0),
    queue_size(2 * m),
    onPersistentOverload(actDie),
    defaultQueueSize(true)
{}

Helper::ChildConfig &
Helper::ChildConfig::updateLimits(const Helper::ChildConfig &rhs)
{
    // Copy the limits only.
    // Preserve the local state values (n_running and n_active)
    n_max = rhs.n_max;
    n_startup = rhs.n_startup;
    n_idle = rhs.n_idle;
    concurrency = rhs.concurrency;
    queue_size = rhs.queue_size;
    onPersistentOverload = rhs.onPersistentOverload;
    defaultQueueSize = rhs.defaultQueueSize;
    return *this;
}

int
Helper::ChildConfig::needNew() const
{
    /* during the startup and reconfigure use our special amount... */
    if (starting_up || reconfiguring) return n_startup;

    /* keep a minimum of n_idle helpers free... */
    if ( (n_active + n_idle) < n_max) return n_idle;

    /* do not ever start more than n_max processes. */
    return (n_max - n_active);
}

void
Helper::ChildConfig::parseConfig()
{
    char *token = ConfigParser::NextToken();

    if (!token) {
        self_destruct();
        return;
    }

    /* starts with a bare number for the max... back-compatible */
    n_max = xatoui(token);

    if (n_max < 1) {
        debugs(0, DBG_CRITICAL, "ERROR: The maximum number of processes cannot be less than 1.");
        self_destruct();
        return;
    }

    /* Parse extension options */
    char *value;
    while (ConfigParser::NextKvPair(token, value)) {
        if (strncmp(token, "startup", 7) == 0) {
            n_startup = xatoui(value);
        } else if (strncmp(token, "idle", 4) == 0) {
            n_idle = xatoui(value);
            if (n_idle < 1) {
                debugs(0, DBG_CRITICAL, "WARNING: OVERRIDE: Using idle=0 for helpers causes request failures. Overriding to use idle=1 instead.");
                n_idle = 1;
            }
        } else if (strncmp(token, "concurrency", 11) == 0) {
            concurrency = xatoui(value);
        } else if (strncmp(token, "queue-size", 10) == 0) {
            queue_size = xatoui(value);
            defaultQueueSize = false;
        } else if (strncmp(token, "on-persistent-overload", 22) == 0) {
            const SBuf action(value);
            if (action.cmp("ERR") == 0)
                onPersistentOverload = actErr;
            else if (action.cmp("die") == 0)
                onPersistentOverload = actDie;
            else {
                debugs(0, DBG_CRITICAL, "ERROR: Unsupported on-persistent-overloaded action: " << action);
                self_destruct();
                return;
            }
        } else if (strncmp(token, "reservation-timeout", 19) == 0)
            reservationTimeout = xatoui(value);
        else if (strncmp(token, "connection-notes", 16) == 0)
            parseNotesList(SBuf(value));
        else {
            debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Undefined option: " << token << ".");
            self_destruct();
            return;
        }
    }

    /* simple sanity. */

    if (n_startup > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING: OVERRIDE: Capping startup=" << n_startup << " to the defined maximum (" << n_max <<")");
        n_startup = n_max;
    }

    if (n_idle > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING: OVERRIDE: Capping idle=" << n_idle << " to the defined maximum (" << n_max <<")");
        n_idle = n_max;
    }

    if (defaultQueueSize)
        queue_size = 2 * n_max;
}

/// parses comma-separated list of key names to be
/// treated like clt_conn_tag
void
Helper::ChildConfig::parseNotesList(const SBuf &buf)
{
    ::Parser::Tokenizer tok(buf);

    static const CharacterSet delims("comma", ",");
    SBuf item;
    while (tok.token(item, delims)) {
        static const SBuf wsp(" ");
        item.trim(wsp);
        if (!item.isEmpty())
            clientConnectionTags.emplace_back(item);
    }
}

void
Helper::ChildConfig::printConfig(StoreEntry *e, const char *directive)
{
    PackableStream os(*e);
    os << "\n" << directive << " " << n_max;

    if (n_startup != 0)
        os << " startup=" << n_startup;

    if (n_idle != 0)
        os << " idle=" << n_idle;

    if (concurrency != 0)
        os << " concurrency=" << concurrency;

    if (!defaultQueueSize)
        os << " queue-size=" << queue_size;

    switch (onPersistentOverload) {
        case actErr:
            os << " on-persistent-overload=ERR";
            break;
        case actDie: // defaults not printed
            break;
    }

    if (reservationTimeout != 64)
        os << " reservation-timeout=" << reservationTimeout;

    static const SBuf comma(",");
    auto cnotes = JoinContainerToSBuf(clientConnectionTags.begin(), clientConnectionTags.end(), comma);
    if (cnotes.cmp("clt_conn_tags") != 0)
        os << " connection-notes=\"" << cnotes << '"';

    os << "\n";
}
