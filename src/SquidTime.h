/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Time Functions */

#ifndef   SQUID_TIME_H
#define   SQUID_TIME_H

#include "rfc1123.h"

#include <ctime>
/* NP: sys/time.h is provided by libcompat */

/* Use uint64_t to store milliseconds */
typedef uint64_t time_msec_t;

/* globals for accessing time */
extern struct timeval current_time;
extern double current_dtime;
extern time_t squid_curtime;

time_t getCurrentTime(void);
int tvSubMsec(struct timeval, struct timeval);

/// timeval substraction operation
/// \param[out] res = t2 - t1
void tvSub(struct timeval &res, struct timeval const &t1, struct timeval const &t2);

/// timeval addition operation
/// \param[out] res = t1 + t2
void tvAdd(struct timeval &res, struct timeval const &t1, struct timeval const &t2);

/// timeval addition assignment operation
/// \param[out] t += add
void tvAssignAdd(struct timeval &t, struct timeval const &add);

/// Convert timeval to milliseconds
inline long int tvToMsec(struct timeval &t)
{
    return t.tv_sec * 1000 + t.tv_usec / 1000;
}

/** event class for doing synthetic time etc */
class TimeEngine
{

public:
    virtual ~TimeEngine();

    /** tick the clock - update from the OS or other time source, */
    virtual void tick();
};

namespace Time
{

/** Display time as a formatted human-readable string.
 * Time syntax is
 * "YYYY/MM/DD hh:mm:ss"
 *
 * Output is only valid until next call to this function.
 */
const char *FormatStrf(time_t t);

/** Display time as a formatted human-readable string.
 * Time string syntax used is that of Apache httpd.
 * "DD/MMM/YYYY:hh:mm:ss zzzz"
 *
 * Output is only valid until next call to this function.
 */
const char *FormatHttpd(time_t t);

} // namespace Time

#endif /* SQUID_TIME_H */

