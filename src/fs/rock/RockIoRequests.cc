/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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

Rock::ReadRequest::ReadRequest(const ::ReadRequest &base, const IoState::Pointer &anSio, const IoXactionId anId):
    ::ReadRequest(base),
     sio(anSio),
     id(anId)
{
}

Rock::WriteRequest::WriteRequest(const ::WriteRequest &base, const IoState::Pointer &anSio, const IoXactionId anId):
    ::WriteRequest(base),
     sio(anSio),
     sidPrevious(-1),
     sidCurrent(-1),
     id(anId),
     eof(false)
{
}

