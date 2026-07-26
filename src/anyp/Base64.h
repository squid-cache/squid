/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ANYP_BASE64_H
#define SQUID_SRC_ANYP_BASE64_H

#include "base/TextException.h"
#include "sbuf/forward.h"

/// Thrown by Base64Decode() when the input is not valid base64.
class DecodeException : public TextException
{
public:
    using TextException::TextException;
};

SBuf Base64Encode(const char *input, size_t length);
SBuf Base64Encode(const SBuf &input);

/// Decodes a base64-encoded string. Throws DecodeException on invalid input.
SBuf Base64Decode(const char *input, size_t length);
SBuf Base64Decode(const SBuf &input);

#endif /* SQUID_SRC_ANYP_BASE64_H */
