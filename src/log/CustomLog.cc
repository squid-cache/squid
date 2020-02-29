/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "log/CustomLog.h"
#include "log/File.h"

bool
CustomLog::usesDaemon() const
{
    return (filename && strncmp(filename, "daemon:", 7) == 0);
}

