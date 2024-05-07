/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTML_QUOTING_H
#define SQUID_SRC_HTML_QUOTING_H

/** Obtain a static buffer containing an HTML-encoded version of the given c-string.
 *
 * HTML reserved characters are replaced with character references
 * per https://html.spec.whatwg.org/#character-references
 */
char *html_quote(const char *);

#endif /* SQUID_SRC_HTML_QUOTING_H */

