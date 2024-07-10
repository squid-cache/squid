/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_XSTRTO_H
#define SQUID_COMPAT_XSTRTO_H

// this function is not used by the remaining Squid C code
#if defined(__cplusplus)

/**
 * Convert a c-string (or its prefix) into an unsigned integer.
 * \param s     input string
 * \param end   like strtoul's "end" pointer
 * \param value pointer for result. Undefined on failure
 * \param min   minimum accepted value
 * \param max   maximum accepted value
 *
 * If @end is nullptr, we assume the caller wants a "strict strtoul", and hence
 * "15a" is rejected.
 * In either case, the value obtained is compared for min-max compliance.
 * Base is always 0, i.e. autodetect depending on @s.
 *
 * \return true/false whether number was accepted. On failure, *value has
 * undefined contents.
 */
bool xstrtoui(const char *s, char **end, unsigned int *value,
              unsigned int min, unsigned int max);

#endif /* __cplusplus */
#endif /* SQUID_COMPAT_XSTRTO_H */

