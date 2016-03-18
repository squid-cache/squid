/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager */

#include "squid.h"

#if USE_DELAY_POOLS
#include "DelayId.h"

#define STUB_API "stub_DelayId.cc"
#include "tests/STUB.h"

DelayId::DelayId(): pool_(0), compositeId(NULL), markedAsNoDelay(false) {}
DelayId::~DelayId() {}

void DelayId::delayRead(DeferredRead const&) STUB_NOP

#endif /* USE_DELAY_POOLS */

