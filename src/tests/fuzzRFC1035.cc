/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "dns/rfc1035.h"

#define kMinInputLength 10
#define kMaxInputLength 5120

extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    rfc1035_message *msg = nullptr;
    rfc1035MessageUnpack(data, size, &msg);
    rfc1035MessageDestroy(&msg);

    return 0;
}
