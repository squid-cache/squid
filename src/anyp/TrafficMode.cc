/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "anyp/TrafficMode.h"

#include <ostream>

void
AnyP::TrafficMode::print(std::ostream &os) const
{
    if (flags_.natIntercept)
        os << " intercept";
    else if (flags_.tproxyIntercept)
        os << " tproxy";
    else if (flags_.accelSurrogate)
        os << " accel";

    if (flags_.tunnelSslBumping)
        os << " ssl-bump";
    if (flags_.proxySurrogate)
        os << " require-proxy-header";
}

