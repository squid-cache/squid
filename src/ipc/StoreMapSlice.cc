/*
 * DEBUG: section 54    Interprocess Communication
 */

#include "squid.h"
#include "ipc/StoreMapSlice.h"
#include "tools.h"

Ipc::StoreMapSlice::StoreMapSlice()
{
    memset(this, 0, sizeof(*this));
}
