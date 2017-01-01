/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_REGISTRATION_H
#define SQUID_MGR_REGISTRATION_H

#include "mgr/forward.h"

namespace Mgr
{

void RegisterAction(char const * action, char const * desc,
                    OBJH * handler,
                    int pw_req_flag, int atomic);

void RegisterAction(char const * action, char const * desc,
                    ClassActionCreationHandler *handler,
                    int pw_req_flag, int atomic);

} // namespace Mgr

#endif /* SQUID_MGR_REGISTRATION_H */

