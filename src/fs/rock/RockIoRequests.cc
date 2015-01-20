/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "fs/rock/RockIoRequests.h"

CBDATA_NAMESPACED_CLASS_INIT(Rock, ReadRequest);
CBDATA_NAMESPACED_CLASS_INIT(Rock, WriteRequest);

Rock::ReadRequest::ReadRequest(const ::ReadRequest &base,
                               const IoState::Pointer &anSio):
    ::ReadRequest(base),
     sio(anSio)
{
}

Rock::WriteRequest::WriteRequest(const ::WriteRequest &base,
                                 const IoState::Pointer &anSio):
    ::WriteRequest(base),
     sio(anSio),
     sidCurrent(-1),
     sidNext(-1),
     eof(false)
{
}

