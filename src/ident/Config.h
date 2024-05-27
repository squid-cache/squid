/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IDENT_CONFIG_H
#define SQUID_SRC_IDENT_CONFIG_H

#if USE_IDENT

#include "acl/Acl.h"
#include "base/Indestructable.h"

namespace Ident
{

class IdentConfig
{
public:
    using AclPointer = Indestructable < RefCount<Acl::Tree> >;

    AclPointer identLookup;
    time_t timeout;
};

extern IdentConfig TheConfig;

} // namespace Ident

#endif /* USE_IDENT */
#endif /* SQUID_SRC_IDENT_CONFIG_H */

