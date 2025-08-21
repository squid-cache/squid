/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_HEADERTOOLS_H
#define SQUID_SRC_HTTP_HEADERTOOLS_H

#include "sbuf/forward.h"

class HttpHeader;
class HttpRequest;

/// A strtoll(10) wrapper that checks for strtoll() failures and other problems.
/// XXX: This function is not fully compatible with some HTTP syntax rules.
/// Just like strtoll(), allows whitespace prefix, a sign, and _any_ suffix.
/// Requires at least one digit to be present.
/// Sets "off" and "end" arguments if and only if no problems were found.
/// \return true if and only if no problems were found.
bool httpHeaderParseOffset(const char *start, int64_t *offPtr, char **endPtr = nullptr);

bool httpHeaderHasConnDir(const HttpHeader * hdr, const SBuf &directive);
int httpHeaderParseInt(const char *start, int *val);
void httpHeaderPutStrf(HttpHeader * hdr, Http::HdrType id, const char *fmt,...) PRINTF_FORMAT_ARG3;

const char *getStringPrefix(const char *str, size_t len);

#endif /* SQUID_SRC_HTTP_HEADERTOOLS_H */

