/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cfg/Exceptions.h"

const char *
Cfg::FatalError::what() const throw()
{
    static const SBuf prefix("FATAL: ");
    static SBuf result;
    result = prefix;
    result.append(message);
    return result.c_str();
}
