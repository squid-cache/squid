/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Base64.h"
#include "base64.h"
#include "sbuf/SBuf.h"

SBuf Base64Encode(const char *input, size_t length)
{
    SBuf result;
    const auto encodedLength = BASE64_ENCODE_RAW_LENGTH(length);
    char *buf = result.rawAppendStart(encodedLength);
    base64_encode_raw(buf, length, reinterpret_cast<const uint8_t *>(input));
    result.rawAppendFinish(buf, encodedLength);
    return result;
}

SBuf Base64Encode(const SBuf &input)
{
    return Base64Encode(input.rawContent(), input.length());
}
