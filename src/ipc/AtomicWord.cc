/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "squid.h"
#include "ipc/AtomicWord.h"
#include "protos.h"

bool Ipc::Atomic::Enabled()
{
#if HAVE_ATOMIC_OPS
    return true;
#else
    return !UsingSmp();
#endif
}
