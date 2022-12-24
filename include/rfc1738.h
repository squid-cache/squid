/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_INCLUDE_RFC1738_H
#define _SQUID_INCLUDE_RFC1738_H

#ifdef __cplusplus
extern "C" {
#endif

/* Encoder rfc1738_do_escape flag values. */
#define RFC1738_ESCAPE_CTRLS       1
#define RFC1738_ESCAPE_UNSAFE      2
#define RFC1738_ESCAPE_RESERVED    4
#define RFC1738_ESCAPE_ALL         (RFC1738_ESCAPE_UNSAFE|RFC1738_ESCAPE_RESERVED|RFC1738_ESCAPE_CTRLS)
// exclusions
#define RFC1738_ESCAPE_NOSPACE     128
#define RFC1738_ESCAPE_NOPERCENT   256
// Backward compatibility
#define RFC1738_ESCAPE_UNESCAPED   (RFC1738_ESCAPE_UNSAFE|RFC1738_ESCAPE_CTRLS|RFC1738_ESCAPE_NOPERCENT)

/**
 * RFC 1738 URL-escaping
 *
 * Public API is formed of a triplet of encode functions mapping to the rfc1738_do_encode() engine.
 *
 * ASCII characters are split into four groups:
 * \li SAFE     Characters which are safe to occur in any URL. For example A,B,C
 * \li CTRLS    Binary control codes. Dangerous to include in URLs.
 * \li UNSAFE   Characters which are completely usafe to occur in any URL. For example; backspace, tab, space, newline.
 * \li RESERVED Characters which are reserved for special meaning and may only occur in certain parts of a URL.
 *
 * Returns a static buffer containing the RFC 1738 compliant, escaped version of the given url.
 *
 * \param flags  RFC1738_ESCAPE_CTRLS     Encode the blatantly dangerous binary codes.
 * \param flags  RFC1738_ESCAPE_UNSAFE    Encode printable unsafe characters (excluding CTRLs).
 * \param flags  RFC1738_ESCAPE_RESERVED  Encode reserved characters.
 * \param flags  RFC1738_ESCAPE_ALL       Encode all binary CTRL, unsafe and reserved characters.
 * \param flags  RFC1738_ESCAPE_NOSPACE   Ignore the space whitespace character.
 * \param flags  RFC1738_ESCAPE_NOPERCENT Ignore the escaping delimiter '%'.
 */
extern char *rfc1738_do_escape(const char *url, int flags);

/* Old API functions */

/* Default RFC 1738 escaping. Escape all UNSAFE characters and binary CTRL codes */
#define rfc1738_escape(x)  rfc1738_do_escape(x, RFC1738_ESCAPE_UNSAFE|RFC1738_ESCAPE_CTRLS)

/* Escape a partial URL. Encoding every binary code, unsafe or reserved character. */
#define rfc1738_escape_part(x)  rfc1738_do_escape(x, RFC1738_ESCAPE_ALL)

/* Escape a URL. Encoding every unsafe characters but skipping reserved and already-encoded bytes.
 * Suitable for safely encoding an absolute URL which may be encoded but is not trusted. */
#define rfc1738_escape_unescaped(x)  rfc1738_do_escape(x, RFC1738_ESCAPE_UNSAFE|RFC1738_ESCAPE_CTRLS|RFC1738_ESCAPE_NOPERCENT)

/**
 * Unescape a URL string according to RFC 1738 specification.
 * String is unescaped in-place
 */
extern void rfc1738_unescape(char *url);

#ifdef __cplusplus
}
#endif
#endif /* _SQUID_INCLUDE_RFC1738_H */

