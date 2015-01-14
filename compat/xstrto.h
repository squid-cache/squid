/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_XSTRTO_H
#define _SQUID_XSTRTO_H

// these functions are not used by the remaining Squid C code.
#if defined(__cplusplus)

#if HAVE_STDBOOL_H
#include <stdbool.h>
#endif

/**
 * xstrtou{i,l} - string to number conversion
 * \param s     input string
 * \param end   like strtoul's "end" pointer
 * \param value pointer for result. Undefined on failure
 * \param min   minimum accepted value
 * \param max   maximum accepted value
 *
 * If @end is NULL, we assume the caller wants a "strict strtoul", and hence
 * "15a" is rejected.
 * In either case, the value obtained is compared for min-max compliance.
 * Base is always 0, i.e. autodetect depending on @s.
 *
 * \return true/false whether number was accepted. On failure, *value has
 * undefined contents.
 */
bool xstrtoul(const char *s, char **end, unsigned long *value,
              unsigned long min, unsigned long max);

bool xstrtoui(const char *s, char **end, unsigned int *value,
              unsigned int min, unsigned int max);

#endif /* __cplusplus */
#endif /* _SQUID_XSTRTO_H */

