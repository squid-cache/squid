/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_FORMAT_QUOTING_H
#define _SQUID_FORMAT_QUOTING_H

#include "sbuf/SBuf.h"

namespace Format
{

/// Safely URL-encode a username.
/// Accepts NULL or empty strings.
char * QuoteUrlEncodeUsername(const char *name);

/** URL-style encoding on a MIME headers blob.
 * May accept NULL or empty strings.
 * \return A dynamically allocated string. recipient is responsible for free()'ing
 */
char *QuoteMimeBlob(const char *header);

/** Double-quote a string.
 * Applies shell-escaping for dquote (") and backslash (\) in the string.
 * May accept empty strings.
 *
 * \return double-quoted string
 */
SBuf DquoteString(const SBuf &);

}; // namespace Format

#endif /* _SQUID_FORMAT_QUOTING_H */

