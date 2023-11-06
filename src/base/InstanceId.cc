/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/InstanceId.h"

#include <iostream>

std::ostream&
operator <<(std::ostream &os, const ScopedId &id)
{
    if (id.value)
        os << id.scope << id.value;
    else if (id.scope)
        os << id.scope;
    else
        os << "[unknown]";
    return os;
}

