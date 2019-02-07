/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/basic/Config.h"
#include "auth/basic/Scheme.h"
#include "Debug.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Basic::Scheme::_instance = NULL;

Auth::Scheme::Pointer
Auth::Basic::Scheme::GetInstance()
{
    if (_instance == NULL) {
        _instance = new Auth::Basic::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Basic::Scheme::type() const
{
    return "basic";
}

void
Auth::Basic::Scheme::shutdownCleanup()
{
    if (_instance == NULL)
        return;

    _instance = NULL;
    debugs(29, DBG_CRITICAL, "Shutdown: Basic authentication.");
}

Auth::Config *
Auth::Basic::Scheme::createConfig()
{
    Auth::Basic::Config *newCfg = new Auth::Basic::Config;
    return dynamic_cast<Auth::Config*>(newCfg);
}

