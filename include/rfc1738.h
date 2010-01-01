#ifndef _SQUID_INCLUDE_RFC1738_H
#define _SQUID_INCLUDE_RFC1738_H

/* for SQUIDCEXTERN */
#include "config.h"


/* Encoder rfc1738_do_escape flag values. */
#define RFC1738_ESCAPE_UNSAFE     0
#define RFC1738_ESCAPE_RESERVED   1
#define RFC1738_ESCAPE_UNESCAPED -1


/**
 * \group rfc1738 RFC 1738 URL-escaping library
 *
 * Public API is formed of a triplet of encode functions mapping to the rfc1738_do_encode() engine.
 *
 * ASCII characters are split into three groups:
 * \item SAFE     Characters which are safe to occur in any URL. For example A,B,C
 * \item UNSAFE   Characters which are completely usafe to occur in any URL. For example; backspace, tab, space, newline
 * \item RESERVED Characters which are reserved for special meaning and may only occur in certain parts of a URL.
 *
 * Returns a static buffer containing the RFC 1738 compliant, escaped version of the given url.
 *
 * \param flags  RFC1738_ESCAPE_UNSAFE    Only encode unsafe characters. Ignore reserved.
 * \param flags  RFC1738_ESCAPE_RESERVED  Encode all unsafe and reserved characters.
 * \param flags  RFC1738_ESCAPE_UNESCAPED Encode all unsafe characters which have not already been encoded.
 */
SQUIDCEXTERN char *rfc1738_do_escape(const char *url, int flags);

/* Old API functions */
#define rfc1738_escape(x)  rfc1738_do_escape(x, RFC1738_ESCAPE_UNSAFE)
#define rfc1738_escape_part(x)  rfc1738_do_escape(x, RFC1738_ESCAPE_RESERVED)
#define rfc1738_escape_unescaped(x)  rfc1738_do_escape(x, RFC1738_ESCAPE_UNESCAPED)


/**
 * Unescape a URL string according to RFC 1738 specification.
 * String is unescaped in-place
 */
SQUIDCEXTERN void rfc1738_unescape(char *url);


#endif /* _SQUID_INCLUDE_RFC1738_H */
