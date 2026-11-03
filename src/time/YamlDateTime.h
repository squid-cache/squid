/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TIME_YAMLDATETIME_H
#define SQUID_SRC_TIME_YAMLDATETIME_H

#include <iosfwd>
#include <sys/time.h>

namespace Time {

/// Output onto an ostream a yaml-formatted datetime string (UTC)
///  see https://yaml.org/type/timestamp.html
class YamlDateTime
{
public:
    YamlDateTime(const struct timeval &tv) : tv_(tv) {};
    void print(std::ostream &) const;

private:
    const struct timeval tv_;
};

} // namespace Time

inline auto &
operator<<(std::ostream &os, const Time::YamlDateTime &dt)
{
    dt.print(os);
    return os;
}

#endif /* SQUID_SRC_TIME_YAMLDATETIME_H */
