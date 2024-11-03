/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TIME_GADGETS_H
#define SQUID_SRC_TIME_GADGETS_H

#include <ctime>
#include <iosfwd>

/* Use uint64_t to store milliseconds */
typedef uint64_t time_msec_t;

/// the current UNIX time in seconds (with microsecond precision)
extern double current_dtime;

/// the current UNIX time in seconds
extern time_t squid_curtime;

/// Update squid_curtime (also current_time, and current_dtime)
/// \returns new value of squid_curtime
time_t getCurrentTime();

namespace Time {

/// Convert from ISO 3307 style time: YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx
time_t ParseIso3307(const char *);

/** Display time as a formatted human-readable string.
 * Time string syntax used is from RFC 1123
 * "www, DD MMM YYYY hh:mm:ss GMT"
 *
 * Output is only valid until next call to this function.
 */
const char *FormatRfc1123(time_t);

/// Convert from RFC 1123 style time: "www, DD MMM YYYY hh:mm:ss ZZZ"
time_t ParseRfc1123(const char *);

/** Display time as a formatted human-readable string.
 * Time syntax is
 * "YYYY/MM/DD hh:mm:ss"
 *
 * Output is only valid until next call to this function.
 */
const char *FormatStrf(time_t);

/** Display time as a formatted human-readable string.
 * Time string syntax used is that of Apache httpd.
 * "DD/MMM/YYYY:hh:mm:ss zzzz"
 *
 * Output is only valid until next call to this function.
*/
const char *FormatHttpd(time_t);

} // namespace Time

/// the current UNIX time in timeval {seconds, microseconds} format
extern struct timeval current_time;

/// timeval subtraction operation.
/// \returns (A-B) in whole microseconds
/// XXX: result is not compatible with time_msec_t millisecond storage
int tvSubUsec(struct timeval A, struct timeval B);

/// timeval subtraction operation.
/// \returns (A-B) in seconds (with microsecond precision)
double tvSubDsec(struct timeval A, struct timeval B);

/// timeval subtraction operation.
/// \returns (A-B) in whole milliseconds
/// XXX: result is not compatible with time_msec_t millisecond storage
int tvSubMsec(struct timeval A, struct timeval B);

/// timeval subtraction operation
/// \param[out] res = t2 - t1
void tvSub(struct timeval &res, struct timeval const &t1, struct timeval const &t2);

/// timeval addition operation
/// \param[out] res = t1 + t2
void tvAdd(struct timeval &res, struct timeval const &t1, struct timeval const &t2);

/// timeval addition assignment operation
/// \param[out] t += add
void tvAssignAdd(struct timeval &t, struct timeval const &add);

/// Convert timeval to milliseconds
/// XXX: result is not compatible with time_msec_t millisecond storage
inline long int tvToMsec(struct timeval &t)
{
    return t.tv_sec * 1000 + t.tv_usec / 1000;
}

/// prints <seconds>.<microseconds>
std::ostream &operator <<(std::ostream &, const timeval &);

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

#endif /* SQUID_SRC_TIME_GADGETS_H */

