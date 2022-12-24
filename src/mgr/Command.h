/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_COMMAND_H
#define SQUID_MGR_COMMAND_H

#include "mgr/ActionParams.h"
#include "mgr/forward.h"

namespace Mgr
{

/// combined hard-coded action profile with user-supplied action parameters
class Command: public RefCountable
{
public:
    typedef RefCount<Command> Pointer;

public:
    ActionProfilePointer profile; ///< hard-coded action specification
    ActionParams params; ///< user-supplied action arguments
};

} // namespace Mgr

std::ostream &operator <<(std::ostream &os, const Mgr::Command &cmd);

#endif /* SQUID_MGR_COMMAND_H */

