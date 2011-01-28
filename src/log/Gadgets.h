#ifndef _SQUID_LOG_GADGETS_H
#define _SQUID_LOG_GADGETS_H

namespace Log
{

/// Safely URL-encode a username.
/// Accepts NULL or empty strings.
char * FormatName(const char *name);

/** URL-style encoding on a MIME headers blob.
 * May accept NULL or empty strings.
 * \return A dynamically allocated string. recipient is responsible for free()'ing
 */
char *QuoteMimeBlob(const char *header);

}; // namespace Log

#endif /* _SQUID_LOG_GADGETS_H */
