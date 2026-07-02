/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base64/Base64Encoder.h"
#include "base64.h"

SBuf Base64Encode(const SBuf &input)
{
    SBuf result;
    const auto encodedLength = BASE64_ENCODE_RAW_LENGTH(input.length());
    char *buf = result.rawAppendStart(encodedLength);
    base64_encode_raw(buf, input.length(), reinterpret_cast<const uint8_t *>(input.rawContent()));
    result.rawAppendFinish(buf, encodedLength);
    return result;
}