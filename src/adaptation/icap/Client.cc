/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/Client.h"
#include "Debug.h"

void Adaptation::Icap::InitModule()
{
    debugs(93,2, HERE << "module enabled.");
}

void Adaptation::Icap::CleanModule()
{
}

