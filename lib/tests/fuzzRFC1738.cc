/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

/* Being a C library code it is best bodily included and tested with C++ type-safe techniques. */
#include "lib/rfc1738.c"

#define kMinInputLength 8
#define kMaxInputLength 1024

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    char *data_in = (char*)calloc(size + 1, sizeof(char));
    memcpy(data_in, data, size);

    rfc1738_unescape(data_in);

    rfc1738_do_escape(data_in, RFC1738_ESCAPE_UNSAFE);
    rfc1738_do_escape(data_in, RFC1738_ESCAPE_RESERVED);
    rfc1738_do_escape(data_in, RFC1738_ESCAPE_UNESCAPED);

    free(data_in);

    return 0;
}
