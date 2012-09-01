/*
 * DEBUG: section 79    Disk IO Routines
 */

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
        sio(anSio)
{
}
