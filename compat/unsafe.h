#ifndef _SQUID_COMPAT_UNSAFE_H
#define _SQUID_COMPAT_UNSAFE_H

/*
 * Trap unintentional use of functions unsafe for use within squid.
 */

#if !SQUID_NO_STRING_BUFFER_PROTECT
#ifndef sprintf
#define sprintf ERROR_sprintf_UNSAFE_IN_SQUID
#endif
#ifndef strdup
#define strdup ERROR_strdup_UNSAFE_IN_SQUID
#endif
#endif /* SQUID_NO_STRING_BUFFER_PROTECT */

#endif /* _SQUID_COMPAT_UNSAFE_H */
