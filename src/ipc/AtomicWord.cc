/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/AtomicWord.h"
#include "tools.h"

bool Ipc::Atomic::Enabled()
{
#if HAVE_ATOMIC_OPS
    return true;
#else
    return !UsingSmp();
#endif
}

