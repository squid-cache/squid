/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/Client.h"
#include "debug/Stream.h"

void Adaptation::Icap::InitModule()
{
    debugs(93,2, "module enabled.");
}

void Adaptation::Icap::CleanModule()
{
}

