/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
operator <<(std::ostream &os, const Mgr::Command &cmd)
{
    if (cmd.profile != NULL)
        return os << *cmd.profile;
    return os << "undef";
}

