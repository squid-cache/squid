/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "mgr/ActionProfile.h"
#include "mgr/Command.h"

std::ostream &
operator <<(std::ostream &os, const Mgr::Command &cmd)
{
    if (cmd.profile != NULL)
        return os << *cmd.profile;
    return os << "undef";
}
