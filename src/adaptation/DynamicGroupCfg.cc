/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "adaptation/DynamicGroupCfg.h"

void
Adaptation::DynamicGroupCfg::add(const String &item)
{
    if (services.empty()) { // first item
        id = item;
    } else {
        id.append(',');
        id.append(item);
    }
    services.push_back(item);
}

void
Adaptation::DynamicGroupCfg::clear()
{
    id.clean();
    services.clear();
}

