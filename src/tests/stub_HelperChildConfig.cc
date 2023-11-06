/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "globals.h"
#include "helper/ChildConfig.h"

#define STUB_API "stub_HelperChildconfig.cc"
#include "tests/STUB.h"

#include <cstring>

Helper::ChildConfig::ChildConfig():
    n_max(0),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0),
    queue_size(0),
    onPersistentOverload(actDie),
    defaultQueueSize(true)
{}

Helper::ChildConfig::ChildConfig(const unsigned int m):
    n_max(m),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0),
    queue_size(2 * m),
    onPersistentOverload(actDie),
    defaultQueueSize(true)
{}

int Helper::ChildConfig::needNew() const STUB_RETVAL(0)
void Helper::ChildConfig::parseConfig() STUB
Helper::ChildConfig & Helper::ChildConfig::updateLimits(const Helper::ChildConfig &) STUB_RETVAL(*this)

