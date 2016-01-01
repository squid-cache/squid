/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Swap Dir base object */

#include "squid.h"
#include "Debug.h"
#include "defines.h"
#include "StoreIOState.h"

void *
StoreIOState::operator new (size_t amount)
{
    assert(0);
    return (void *)1;
}

void
StoreIOState::operator delete (void *address) {assert (0);}

StoreIOState::StoreIOState() :
    swap_dirn(-1), swap_filen(-1), e(NULL), mode(O_BINARY),
    offset_(0), file_callback(NULL), callback(NULL), callback_data(NULL)
{
    read.callback = NULL;
    read.callback_data = NULL;
    flags.closing = false;
}

off_t
StoreIOState::offset() const
{
    return offset_;
}

StoreIOState::~StoreIOState()
{
    debugs(20,3, "StoreIOState::~StoreIOState: " << this);

    if (read.callback_data)
        cbdataReferenceDone(read.callback_data);

    if (callback_data)
        cbdataReferenceDone(callback_data);
}

