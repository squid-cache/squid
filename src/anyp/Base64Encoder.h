/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE64_BASE64ENCODER_H
#define SQUID_SRC_BASE64_BASE64ENCODER_H

#include "sbuf/SBuf.h"

SBuf Base64Encode(const char *input, size_t length);
SBuf Base64Encode(const SBuf &input);

#endif /* SQUID_SRC_BASE64_BASE64ENCODER_H */
