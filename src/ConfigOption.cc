/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#include "squid.h"
#include "ConfigOption.h"

ConfigOptionVector::~ConfigOptionVector()
{
    while (!options.empty()) {
        delete options.back();
        options.pop_back();
    }
}

bool
ConfigOptionVector::parse(char const *option, const char *value, int isaReconfig)
{
    std::vector<ConfigOption *>::iterator i = options.begin();

    while (i != options.end()) {
        if ((*i)->parse(option,value, isaReconfig))
            return true;

        ++i;
    }

    return false;
}

void
ConfigOptionVector::dump(StoreEntry * e) const
{
    for (std::vector<ConfigOption *>::const_iterator i = options.begin();
            i != options.end(); ++i)
        (*i)->dump(e);
}

