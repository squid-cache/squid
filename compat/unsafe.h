#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef _SQUID_COMPAT_UNSAFE_H
#define _SQUID_COMPAT_UNSAFE_H

/*
 * Trap unintentional use of functions unsafe for use within squid.
 */

#if !SQUID_NO_ALLOC_PROTECT
#ifndef free
#define free(x) ERROR_free_UNSAFE_IN_SQUID(x)
#endif
#ifndef malloc
#define malloc ERROR_malloc_UNSAFE_IN_SQUID
#endif
#ifndef calloc
#define calloc ERROR_calloc_UNSAFE_IN_SQUID
#endif
#endif /* !SQUID_NO_ALLOC_PROTECT */

#if !SQUID_NO_STRING_BUFFER_PROTECT
#ifndef sprintf
#define sprintf ERROR_sprintf_UNSAFE_IN_SQUID
#endif
#ifndef strdup
#define strdup ERROR_strdup_UNSAFE_IN_SQUID
#endif
#endif /* SQUID_NO_STRING_BUFFER_PROTECT */

#endif /* _SQUID_COMPAT_UNSAFE_H */
