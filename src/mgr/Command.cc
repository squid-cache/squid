/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "mgr/ActionProfile.h"
#include "mgr/Command.h"

std::ostream &
Mgr::operator <<(std::ostream &os, const Command &cmd)
{
    if (cmd.profile != nullptr)
        return os << *cmd.profile;
    return os << "undef";
}

