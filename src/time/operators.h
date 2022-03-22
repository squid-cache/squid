/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_TIME_OPERATORS_H
#define SQUID__SRC_TIME_OPERATORS_H

// TODO: Remove direct timercmp() calls in legacy code.

inline bool
operator <(const timeval &a, const timeval &b)
{
    return timercmp(&a, &b, <);
}

inline bool
operator >(const timeval &a, const timeval &b)
{
    return timercmp(&a, &b, >);
}

inline bool
operator !=(const timeval &a, const timeval &b)
{
    return timercmp(&a, &b, !=);
}

// Operators for timeval below avoid timercmp() because Linux timeradd(3) manual
// page says that their timercmp() versions "do not work" on some platforms.

inline bool
operator <=(const timeval &a, const timeval &b)
{
    return !(a > b);
}

inline bool
operator >=(const timeval &a, const timeval &b)
{
    return !(a < b);
}

inline bool
operator ==(const timeval &a, const timeval &b)
{
    return !(a != b);
}

#endif /* SQUID__SRC_TIME_OPERATORS_H */
