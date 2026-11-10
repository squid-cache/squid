/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "globals.h"
#include "helper/ChildConfig.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

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
    auto squidConf = Configuration::LegacyParser();

    /* starts with a bare number for the max... back-compatible */
    ::Parser::Tokenizer tok(squidConf.token("maximum number of helper processes"));
    n_max = tok.udec64("max");
    if (n_max < 1)
        throw TextException("maximum number of helper processes cannot be less than 1", Here());

    /* Parse extension options */
    char *key;
    char *value;
    while (squidConf.optionalKvPair(key, value)) {
        tok.reset(SBuf(value));
        if (strcmp(key, "startup") == 0) {
            n_startup = tok.udec64(key);
            if (n_startup > n_max)
                throw TextException(ToSBuf("option startup=", value, " cannot exceed maximum number of processes (", n_max, ")"), Here());

        } else if (strcmp(key, "idle") == 0) {
            n_idle = tok.udec64(key);
            if (n_idle < 1)
                throw TextException(ToSBuf("option ", key, "=", value, " must be at least 1"), Here());
            if (n_idle > n_max)
                throw TextException(ToSBuf("option ", key, "=", value, " cannot exceed maximum number of processes (", n_max, ")"), Here());

        } else if (strcmp(key, "concurrency") == 0) {
            concurrency = tok.udec64(key);

        } else if (strcmp(key, "queue-size") == 0) {
            queue_size = tok.udec64(key);
            defaultQueueSize = false;

        } else if (strcmp(key, "on-persistent-overload") == 0) {
            if (tok.buf().cmp("ERR") == 0)
                onPersistentOverload = actErr;
            else if (tok.buf().cmp("die") == 0)
                onPersistentOverload = actDie;
            else
                throw TextException(ToSBuf("unsupported on-persistent-overloaded action: ", value), Here());

        } else if (strcmp(key, "reservation-timeout") == 0) {
            reservationTimeout = tok.udec64(key);

        } else {
            throw TextException(ToSBuf("undefined option: ", key), Here());
        }
    }

    if (defaultQueueSize)
        queue_size = 2 * n_max;
}

