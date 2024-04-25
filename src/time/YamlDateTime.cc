/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "YamlDateTime.h"

#include <ctime>
#include <iomanip>
#include <ostream>

void
Time::YamlDateTime::print(std::ostream &os) const
{
    // need to add fractions and timezone on top of this
    static const char *yaml_time_format = "%Y-%m-%d %H:%M:%S";
    const auto tm = gmtime(&tv_.tv_sec);
    os << std::put_time(tm, yaml_time_format);
    os << '.' << std::setw(2) << (tv_.tv_usec / 10000) << 'Z';
}
