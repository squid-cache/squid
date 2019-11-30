/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_CHARSET_H
#define _SQUID_CHARSET_H

#include "sbuf/forward.h"

/// converts ISO-LATIN-1 to UTF-8
SBuf Latin1ToUtf8(const char *in);

/// converts CP1251 to UTF-8
SBuf Cp1251ToUtf8(const char *in);

/// returns whether the given input is a valid (or empty) sequence of UTF-8 code points
bool isValidUtf8String(const char *source, const char *sourceEnd);

#endif /* _SQUID_CHARSET_H */

