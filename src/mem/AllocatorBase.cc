/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/AllocatorBase.h"
#include "mem/Pool.h"

size_t
Mem::AllocatorBase::RoundedSize(size_t s)
{
    return ((s + sizeof(void*) - 1) / sizeof(void*)) * sizeof(void*);
}
