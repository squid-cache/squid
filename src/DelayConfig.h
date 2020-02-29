/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration Settings */

#ifndef SQUID_DELAYCONFIG_H
#define SQUID_DELAYCONFIG_H

class StoreEntry;
class ConfigParser;

/// \ingroup DelayPoolsAPI
class DelayConfig
{

public:
    void freePoolCount();
    void dumpPoolCount(StoreEntry * entry, const char *name) const;
    void parsePoolCount();
    void parsePoolClass();
    void parsePoolRates();
    void parsePoolAccess(ConfigParser &parser);
    unsigned short initial;

};

#endif /* SQUID_DELAYCONFIG_H */

