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

SBuf Base64Decode(const char *input, size_t length)
{
    struct base64_decode_ctx ctx;
    base64_decode_init(&ctx);

    SBuf result;
    const auto maxDecodedLength = BASE64_DECODE_LENGTH(length);
    uint8_t *buf = reinterpret_cast<uint8_t *>(result.rawAppendStart(maxDecodedLength));

    size_t decodedLength = 0;
    if (!base64_decode_update(&ctx, &decodedLength, buf, length, input))
        throw DecodeException("base64 decode error: invalid input", Here());
    if (!base64_decode_final(&ctx))
        throw DecodeException("base64 decode error: incomplete input", Here());

    result.rawAppendFinish(reinterpret_cast<char *>(buf), decodedLength);
    return result;
}

SBuf Base64Decode(const SBuf &input)
{
    return Base64Decode(input.rawContent(), input.length());
}
