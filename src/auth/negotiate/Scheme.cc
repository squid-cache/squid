/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/negotiate/Config.h"
#include "auth/negotiate/Scheme.h"
#include "Debug.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Negotiate::Scheme::_instance = NULL;

Auth::Scheme::Pointer
Auth::Negotiate::Scheme::GetInstance()
{
    if (_instance == NULL) {
        _instance = new Auth::Negotiate::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Negotiate::Scheme::type() const
{
    return "negotiate";
}

void
Auth::Negotiate::Scheme::shutdownCleanup()
{
    if (_instance == NULL)
        return;

    _instance = NULL;
    debugs(29, DBG_CRITICAL, "Shutdown: Negotiate authentication.");
}

Auth::Config *
Auth::Negotiate::Scheme::createConfig()
{
    Auth::Negotiate::Config *negotiateCfg = new Auth::Negotiate::Config;
    return dynamic_cast<Auth::Config*>(negotiateCfg);
}

